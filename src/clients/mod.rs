use crate::clients::directory::presence::Topology;
use crate::clients::mix::MixClient;
use crate::clients::provider::ProviderClient;
use crate::sockets::ws;
use crate::utils;
use crate::utils::topology::get_topology;
use futures::channel::mpsc;
use futures::future::join5;
use futures::select;
use futures::{SinkExt, StreamExt};
use sphinx::route::{Destination, DestinationAddressBytes, NodeAddressBytes};
use sphinx::SphinxPacket;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::time::Duration;
use tokio::runtime::Runtime;
use sfw_provider_requests::requests::AuthToken;

pub mod directory;
pub mod mix;
pub mod provider;
pub mod validator;

// TODO: put that in config once it exists
const LOOP_COVER_AVERAGE_DELAY: f64 = 10.0;
// assume seconds
const MESSAGE_SENDING_AVERAGE_DELAY: f64 = 10.0;
// assume seconds;
const FETCH_MESSAGES_DELAY: f64 = 10.0; // assume seconds;

// provider-poller sends polls service provider; receives messages
// provider-poller sends (TX) to ReceivedBufferController (RX)
// ReceivedBufferController sends (TX) to ... ??Client??
// outQueueController sends (TX) to TrafficStreamController (RX)
// TrafficStreamController sends messages to mixnet
// ... ??Client?? sends (TX) to outQueueController (RX)
// Loop cover traffic stream just sends messages to mixnet without any channel communication

struct MixMessage(NodeAddressBytes, SphinxPacket);

struct MixTrafficController;

impl MixTrafficController {
    // this was way more difficult to implement than what this code may suggest...
    async fn run(mut rx: mpsc::UnboundedReceiver<MixMessage>) {
        let mix_client = MixClient::new();
        while let Some(mix_message) = rx.next().await {
            println!(
                "[MIX TRAFFIC CONTROL] - got a mix_message for {:?}",
                mix_message.0
            );
            let send_res = mix_client.send(mix_message.1, mix_message.0).await;
            match send_res {
                Ok(_) => println!("We successfully sent the message!"),
                Err(e) => eprintln!("We failed to send the message :( - {:?}", e),
            };
        }
    }
}

pub struct NymClient {
    // to be replaced by something else I guess
    address: DestinationAddressBytes,
    pub input_tx: mpsc::UnboundedSender<InputMessage>,
    // to be used by "send" function or socket, etc
    input_rx: mpsc::UnboundedReceiver<InputMessage>,
    socket_listening_address: SocketAddr,
    is_local: bool,
    auth_token: Option<AuthToken>
}

#[derive(Debug)]
pub struct InputMessage(pub Destination, pub Vec<u8>);

impl NymClient {
    pub fn new(address: DestinationAddressBytes, socket_listening_address: SocketAddr, is_local: bool, auth_token: Option<AuthToken>) -> Self {
        let (input_tx, input_rx) = mpsc::unbounded::<InputMessage>();

        NymClient {
            address,
            input_tx,
            input_rx,
            socket_listening_address,
            is_local,
            auth_token,
        }
    }

    async fn start_loop_cover_traffic_stream(
        mut tx: mpsc::UnboundedSender<MixMessage>,
        our_info: Destination,
        topology: Topology,
    ) {
        loop {
            println!("[LOOP COVER TRAFFIC STREAM] - next cover message!");
            let delay = utils::poisson::sample(LOOP_COVER_AVERAGE_DELAY);
            let delay_duration = Duration::from_secs_f64(delay);
            tokio::time::delay_for(delay_duration).await;
            let cover_message =
                utils::sphinx::loop_cover_message(our_info.address, our_info.identifier, &topology);
            tx.send(MixMessage(cover_message.0, cover_message.1))
                .await
                .unwrap();
        }
    }

    async fn control_out_queue(
        mut mix_tx: mpsc::UnboundedSender<MixMessage>,
        mut input_rx: mpsc::UnboundedReceiver<InputMessage>,
        our_info: Destination,
        topology: Topology,
    ) {
        loop {
            println!("[OUT QUEUE] here I will be sending real traffic (or loop cover if nothing is available)");
            select! {
                real_message = input_rx.next() => {
                    println!("[OUT QUEUE] - we got a real message!");
                    let real_message = real_message.expect("The channel must have closed! - if the client hasn't crashed, it should have!");
                    println!("real: {:?}", real_message);
                    let encapsulated_message = utils::sphinx::encapsulate_message(real_message.0, real_message.1, &topology);
                    mix_tx.send(MixMessage(encapsulated_message.0, encapsulated_message.1)).await.unwrap();
                },

                default => {
                    println!("[OUT QUEUE] - no real message - going to send extra loop cover");
                    let cover_message = utils::sphinx::loop_cover_message(our_info.address, our_info.identifier, &topology);
                    mix_tx.send(MixMessage(cover_message.0, cover_message.1)).await.unwrap();
                }
            };

            let delay_duration = Duration::from_secs_f64(MESSAGE_SENDING_AVERAGE_DELAY);
            tokio::time::delay_for(delay_duration).await;
        }
    }

    async fn start_provider_polling(provider_address: SocketAddrV4) {
        let provider_client = ProviderClient::new(provider_address);

        loop {
            println!("[FETCH MSG] - Polling provider...");
            let delay_duration = Duration::from_secs_f64(FETCH_MESSAGES_DELAY);
            tokio::time::delay_for(delay_duration).await;
            provider_client
                .retrieve_messages()
                .await
                .unwrap();
        }
    }

    pub fn start(self) -> Result<(), Box<dyn std::error::Error>> {
        println!("starting nym client");


        match self.auth_token {
            None => println!("Need to register!"),
            Some(token) => println!("Already got the token! - {:?}", token),
        }
        // TODO: registration here

        return Ok(());
        // don't start anything, just register

        let (mix_tx, mix_rx) = mpsc::unbounded();
        let mut rt = Runtime::new()?;
        let topology = get_topology(self.is_local);
        let provider_address: SocketAddrV4 = topology
            .mix_provider_nodes
            .first()
            .unwrap()
            .host
            .parse()
            .unwrap();

        let mix_traffic_future = rt.spawn(MixTrafficController::run(mix_rx));
        let loop_cover_traffic_future = rt.spawn(NymClient::start_loop_cover_traffic_stream(
            mix_tx.clone(),
            Destination::new(self.address, Default::default()),
            topology.clone(),
        ));

        let out_queue_control_future = rt.spawn(NymClient::control_out_queue(
            mix_tx,
            self.input_rx,
            Destination::new(self.address, Default::default()),
            topology.clone(),
        ));

        let provider_polling_future = rt.spawn(NymClient::start_provider_polling(provider_address));
        let websocket_future = rt.spawn(ws::start_websocket(self.socket_listening_address, self.input_tx));

        rt.block_on(async {
            let future_results = join5(
                mix_traffic_future,
                loop_cover_traffic_future,
                out_queue_control_future,
                provider_polling_future,
                websocket_future,
            )
            .await;
            assert!(
                future_results.0.is_ok()
                    && future_results.1.is_ok()
                    && future_results.2.is_ok()
                    && future_results.3.is_ok()
                    && future_results.4.is_ok()
            );
        });

        // this line in theory should never be reached as the runtime should be permanently blocked on traffic senders
        eprintln!("The client went kaput...");
        Ok(())
    }
}
