use client_core::{client::base_client::non_wasm_helpers, config::DebugConfig};
use nym_sdk::mixnet;

#[tokio::main]
async fn main() {
    logging::setup_logging();

    // Create client builder, including ephemeral keys. The builder can be usable in the context
    // where you don't want to connect just yet
    let client = mixnet::MixnetClientBuilder::new(None, None).await.unwrap();
    //let debug_config = DebugConfig::default();
    //let empty_storage = non_wasm_helpers::setup_empty_reply_surb_backend(&debug_config);
    //let client = mixnet::MixnetClientBuilder::new_with_custom_storage(None, None, empty_storage).unwrap();

    // Now we connect to the mixnet, using ephemeral keys already created
    let mut client = client.connect_to_mixnet().await.unwrap();

    // Be able to get our client address
    let our_address = client.nym_address();
    println!("Our client nym address is: {our_address}");

    // Send a message throught the mixnet to ourselves
    client
        .send_str(&our_address.to_string(), "hello there")
        .await;

    println!("Waiting for message");
    client
        .on_messages(|msg| println!("Received: {}", String::from_utf8_lossy(&msg.message)))
        .await;
}
