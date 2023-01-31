// Copyright 2021 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0

use crate::client::replies::reply_controller::ReplyControllerSender;
use crate::client::replies::reply_storage::SentReplyKeys;
use crate::spawn_future;
use crypto::asymmetric::encryption;
use crypto::Digest;
use futures::channel::mpsc;
use futures::lock::Mutex;
use futures::StreamExt;
use gateway_client::packet_router::LogMixnetMessage;
use gateway_client::MixnetMessageReceiver;
use log::*;
use nymsphinx::anonymous_replies::requests::{
    RepliableMessage, RepliableMessageContent, ReplyMessage, ReplyMessageContent,
};
use nymsphinx::anonymous_replies::{encryption_key::EncryptionKeyDigest, SurbEncryptionKey};
use nymsphinx::message::{NymMessage, PlainMessage};
use nymsphinx::params::ReplySurbKeyDigestAlgorithm;
use nymsphinx::receiver::{MessageReceiver, MessageRecoveryError, ReconstructedMessage};
use std::collections::HashSet;
use std::sync::Arc;

// Buffer Requests to say "hey, send any reconstructed messages to this channel"
// or to say "hey, I'm going offline, don't send anything more to me. Just buffer them instead"
pub type ReceivedBufferRequestSender = mpsc::UnboundedSender<ReceivedBufferMessage>;
pub type ReceivedBufferRequestReceiver = mpsc::UnboundedReceiver<ReceivedBufferMessage>;

// The channel set for the above
pub type ReconstructedMessagesSender = mpsc::UnboundedSender<Vec<ReconstructedMessage>>;
pub type ReconstructedMessagesReceiver = mpsc::UnboundedReceiver<Vec<ReconstructedMessage>>;

struct ReceivedMessagesBufferInner {
    messages: Vec<ReconstructedMessage>,
    local_encryption_keypair: Arc<encryption::KeyPair>,

    // TODO: looking how it 'looks' here, perhaps `MessageReceiver` should be renamed to something
    // else instead.
    message_receiver: MessageReceiver,
    message_sender: Option<ReconstructedMessagesSender>,

    // TODO: this will get cleared upon re-running the client
    // but perhaps it should be changed to include timestamps of when the message was reconstructed
    // and every now and then remove ids older than X
    recently_reconstructed: HashSet<i32>,
}

impl ReceivedMessagesBufferInner {
    fn recover_from_fragment(
        &mut self,
        fragment_data: &[u8],
        log_unassociated_fragment_id: Option<u64>, // present (received message from gateway), or absent (received control response / reply)
    ) -> Option<NymMessage> {
        if nymsphinx::cover::is_cover(fragment_data) {
            trace!("The message was a loop cover message! Skipping it");
            // Self note: Instead of if let, I previously used .expect() here, and led to an
            // extremely hard to chase bug: this line crashed its runner thread but the error
            // wasn't shown in Android Studio. It crashed because control responses (received only
            // during setup) passed through this method,
            // ! TODO IMPT: std:err is still lost: .expect() and panic!() won't show up in Android
            // ! Studio. Need to use log::error explicitly.
            if let Some(log_unassociated_fragment_id) = log_unassociated_fragment_id {
                log::info!(
                    "tK=c l=LOOP_COVER/LOOP_COVER_REAL ufId={}",
                    log_unassociated_fragment_id
                );
            } else {
                log::error!("recover_from_fragment encountered message without ufId: presumably a control response?")
            }
            return None;
        }

        // It should be fair to assume from here on that log_unassociated_fragment_id is Some.
        // If not (e.g. in the future when logging reply stuffs), need to change all such
        // assumptions through the execution sequence. (e.g. turning u64s into Option<u64>s)
        // CTRL+F in project: "Assumes that fragment's log_unassociated_fragment_id is Some"

        let fragment = match self
            .message_receiver
            .recover_fragment(fragment_data, log_unassociated_fragment_id)
        {
            Err(err) => {
                warn!("failed to recover fragment from raw data: {err}. The whole underlying message might be corrupted and unrecoverable!");
                return None;
            }
            Ok(frag) => frag,
        };

        if self.recently_reconstructed.contains(&fragment.id()) {
            debug!("Received a chunk of already re-assembled message ({:?})! It probably got here because the ack got lost", fragment.id());
            return None;
        }

        // if we returned an error the underlying message is malformed in some way
        match self.message_receiver.insert_new_fragment(fragment) {
            Err(err) => match err {
                MessageRecoveryError::MalformedReconstructedMessage { source, used_sets } => {
                    error!("message reconstruction failed - {source}. Attempting to re-use the message sets...");
                    // TODO: should we really insert reconstructed sets? could this be abused for some attack?
                    for set_id in used_sets {
                        if !self.recently_reconstructed.insert(set_id) {
                            // or perhaps we should even panic at this point?
                            error!("Reconstructed another message containing already used set id!")
                        }
                    }
                    None
                }
                _ => unreachable!(
                    "no other error kind should have been returned here! If so, it's a bug!"
                ),
            },
            Ok(reconstruction_result) => match reconstruction_result {
                Some((reconstructed_message, used_sets)) => {
                    for set_id in used_sets {
                        if !self.recently_reconstructed.insert(set_id) {
                            // or perhaps we should even panic at this point?
                            error!("Reconstructed another message containing already used set id!")
                        }
                    }
                    Some(reconstructed_message)
                }
                None => None,
            },
        }
    }

    fn process_received_reply(
        &mut self,
        reply_ciphertext: &mut [u8],
        reply_key: SurbEncryptionKey,
    ) -> Option<NymMessage> {
        // note: this performs decryption IN PLACE without extra allocation
        self.message_receiver
            .recover_plaintext_from_reply(reply_ciphertext, reply_key);
        let fragment_data = reply_ciphertext;

        self.recover_from_fragment(
            fragment_data,
            None, // I'm not logging stuff related to replies yet
        )
    }

    fn process_received_regular_packet(
        &mut self,
        mut raw_fragment: Vec<u8>,
        log_unassociated_fragment_id: Option<u64>, // present (received message from gateway), or absent (received control response)
    ) -> Option<NymMessage> {
        let fragment_data = match self.message_receiver.recover_plaintext_from_regular_packet(
            self.local_encryption_keypair.private_key(),
            &mut raw_fragment,
        ) {
            Err(err) => {
                warn!("failed to recover fragment data: {err}. The whole underlying message might be corrupted and unrecoverable!");
                return None;
            }
            Ok(frag_data) => frag_data,
        };

        self.recover_from_fragment(fragment_data, log_unassociated_fragment_id)
    }
}

#[derive(Debug, Clone)]
// Note: you should NEVER create more than a single instance of this using 'new()'.
// You should always use .clone() to create additional instances
struct ReceivedMessagesBuffer {
    inner: Arc<Mutex<ReceivedMessagesBufferInner>>,
    reply_key_storage: SentReplyKeys,
    reply_controller_sender: ReplyControllerSender,
}

impl ReceivedMessagesBuffer {
    fn new(
        local_encryption_keypair: Arc<encryption::KeyPair>,
        reply_key_storage: SentReplyKeys,
        reply_controller_sender: ReplyControllerSender,
    ) -> Self {
        ReceivedMessagesBuffer {
            inner: Arc::new(Mutex::new(ReceivedMessagesBufferInner {
                messages: Vec::new(),
                local_encryption_keypair,
                message_receiver: MessageReceiver::new(),
                message_sender: None,
                recently_reconstructed: HashSet::new(),
            })),
            reply_key_storage,
            reply_controller_sender,
        }
    }

    async fn disconnect_sender(&mut self) {
        let mut guard = self.inner.lock().await;
        if guard.message_sender.is_none() {
            // in theory we could just ignore it, but that situation should have never happened
            // in the first place, so this way we at least know we have an important bug to fix
            panic!("trying to disconnect non-existent sender!")
        }
        guard.message_sender = None;
    }

    async fn connect_sender(&mut self, sender: ReconstructedMessagesSender) {
        let mut guard = self.inner.lock().await;
        if guard.message_sender.is_some() {
            // in theory we could just ignore it, but that situation should have never happened
            // in the first place, so this way we at least know we have an important bug to fix
            panic!("trying overwrite an existing sender!")
        }

        // while we're at it, also empty the buffer if we happened to receive anything while
        // no sender was connected
        let stored_messages = std::mem::take(&mut guard.messages);
        if !stored_messages.is_empty() {
            if let Err(err) = sender.unbounded_send(stored_messages) {
                error!(
                    "The sender channel we just received is already invalidated - {:?}",
                    err
                );
                // put the values back to the buffer
                // the returned error has two fields: err: SendError and val: T,
                // where val is the value that was failed to get sent;
                // it's returned by the `into_inner` call
                guard.messages = err.into_inner();
                return;
            }
        }
        guard.message_sender = Some(sender);
    }

    fn handle_reconstructed_plain_messages(
        &mut self,
        msgs: Vec<PlainMessage>,
    ) -> Vec<ReconstructedMessage> {
        msgs.into_iter().map(Into::into).collect()
    }

    fn handle_reconstructed_repliable_messages(
        &mut self,
        msgs: Vec<RepliableMessage>,
    ) -> Vec<ReconstructedMessage> {
        let mut reconstructed = Vec::new();
        for msg in msgs {
            let (reply_surbs, from_surb_request) = match msg.content {
                RepliableMessageContent::Data {
                    message,
                    reply_surbs,
                } => {
                    trace!(
                        "received message that also contained additional {} reply surbs from {:?}!",
                        reply_surbs.len(),
                        msg.sender_tag
                    );

                    reconstructed.push(ReconstructedMessage::new(message, msg.sender_tag));

                    (reply_surbs, false)
                }
                RepliableMessageContent::AdditionalSurbs { reply_surbs } => {
                    trace!(
                        "received additional {} reply surbs from {:?}!",
                        reply_surbs.len(),
                        msg.sender_tag
                    );
                    (reply_surbs, true)
                }
                RepliableMessageContent::Heartbeat {
                    additional_reply_surbs,
                } => {
                    error!("received a repliable heartbeat message - we don't know how to handle it yet (and we won't know until future PRs)");
                    (additional_reply_surbs, false)
                }
            };

            self.reply_controller_sender.send_additional_surbs(
                msg.sender_tag,
                reply_surbs,
                from_surb_request,
            )
        }
        reconstructed
    }

    fn handle_reconstructed_reply_messages(
        &mut self,
        msgs: Vec<ReplyMessage>,
    ) -> Vec<ReconstructedMessage> {
        let mut reconstructed = Vec::new();
        for msg in msgs {
            match msg.content {
                ReplyMessageContent::Data { message } => reconstructed.push(
                    PlainMessage {
                        inner: message,
                        log_message_id: None, // I'm not logging stuff related to replies yet
                        log_associator_unassociated_fragment_id: None, // I'm not logging stuff related to replies yet
                    }
                    .into(),
                ),
                ReplyMessageContent::SurbRequest { recipient, amount } => {
                    debug!("received request for {amount} additional reply SURBs from {recipient}");
                    self.reply_controller_sender
                        .send_additional_surbs_request(*recipient, amount);
                }
            }
        }
        reconstructed
    }

    async fn handle_reconstructed_messages(&mut self, msgs: Vec<NymMessage>) {
        if msgs.is_empty() {
            return;
        }

        // FIND OUT WHERE TO PUT T7.
        let mut plain_messages = Vec::new();
        let mut repliable_messages = Vec::new();
        let mut reply_messages = Vec::new();

        for msg in msgs {
            match msg {
                NymMessage::Plain(plain) => plain_messages.push(plain),
                NymMessage::Repliable(repliable) => repliable_messages.push(repliable),
                NymMessage::Reply(reply) => reply_messages.push(reply),
            }
        }

        let mut reconstructed_messages = self.handle_reconstructed_plain_messages(plain_messages);
        reconstructed_messages
            .append(&mut self.handle_reconstructed_repliable_messages(repliable_messages));
        reconstructed_messages
            .append(&mut self.handle_reconstructed_reply_messages(reply_messages));

        let mut inner_guard = self.inner.lock().await;
        debug!(
            "Adding {:?} new messages to the buffer!",
            reconstructed_messages.len()
        );

        if let Some(sender) = &inner_guard.message_sender {
            trace!("Sending reconstructed messages to announced sender");
            if let Err(err) = sender.unbounded_send(reconstructed_messages) {
                warn!("The reconstructed message receiver went offline without explicit notification (relevant error: - {err})");
                inner_guard.message_sender = None;
                inner_guard.messages.extend(err.into_inner());
            }
        } else {
            trace!("No sender available - buffering reconstructed messages");
            inner_guard.messages.extend(reconstructed_messages)
        }
    }

    // this function doesn't really belong here...
    fn get_reply_key<'a>(
        &self,
        raw_message: &'a mut [u8],
    ) -> Option<(SurbEncryptionKey, &'a mut [u8])> {
        let reply_surb_digest_size = ReplySurbKeyDigestAlgorithm::output_size();
        if raw_message.len() < reply_surb_digest_size {
            return None;
        }

        let possible_key_digest =
            EncryptionKeyDigest::clone_from_slice(&raw_message[..reply_surb_digest_size]);
        self.reply_key_storage
            .try_pop(possible_key_digest)
            .map(|reply_encryption_key| {
                (
                    *reply_encryption_key,
                    &mut raw_message[reply_surb_digest_size..],
                )
            })
    }

    async fn handle_new_received(&mut self, msgs: Vec<LogMixnetMessage>) {
        trace!(
            "Processing {:?} new message that might get added to the buffer!",
            msgs.len()
        );

        let mut completed_messages = Vec::new();
        let mut inner_guard = self.inner.lock().await;

        // first check if this is a reply or a chunked message
        // note: there's a possible information leakage associated with this check https://github.com/nymtech/nym/issues/296
        for mut msg in msgs {
            // check first `HasherOutputSize` bytes if they correspond to known encryption key
            // if yes - this is a reply message
            let completed_message = if let Some((reply_key, reply_message)) =
                self.get_reply_key(&mut msg.inner)
            {
                inner_guard.process_received_reply(reply_message, reply_key)
            } else {
                inner_guard
                    .process_received_regular_packet(msg.inner, msg.log_unassociated_fragment_id)
            };

            if let Some(completed) = completed_message {
                info!("received {completed}");
                completed_messages.push(completed)
            }
        }

        drop(inner_guard);

        if !completed_messages.is_empty() {
            self.handle_reconstructed_messages(completed_messages).await
        }
    }
}

pub enum ReceivedBufferMessage {
    // Signals a websocket connection (or a native implementation) was established and we should stop buffering messages,
    // and instead send them directly to the received channel
    ReceiverAnnounce(ReconstructedMessagesSender),

    // Explicit signal that Receiver connection will no longer accept messages
    ReceiverDisconnect,
}

struct RequestReceiver {
    received_buffer: ReceivedMessagesBuffer,
    query_receiver: ReceivedBufferRequestReceiver,
}

impl RequestReceiver {
    fn new(
        received_buffer: ReceivedMessagesBuffer,
        query_receiver: ReceivedBufferRequestReceiver,
    ) -> Self {
        RequestReceiver {
            received_buffer,
            query_receiver,
        }
    }

    async fn handle_message(&mut self, message: ReceivedBufferMessage) {
        match message {
            ReceivedBufferMessage::ReceiverAnnounce(sender) => {
                self.received_buffer.connect_sender(sender).await;
            }
            ReceivedBufferMessage::ReceiverDisconnect => {
                self.received_buffer.disconnect_sender().await
            }
        }
    }

    async fn run_with_shutdown(&mut self, mut shutdown: task::ShutdownListener) {
        debug!("Started RequestReceiver with graceful shutdown support");
        while !shutdown.is_shutdown() {
            tokio::select! {
                biased;
                _ = shutdown.recv() => {
                    log::trace!("RequestReceiver: Received shutdown");
                }
                request = self.query_receiver.next() => {
                    match request {
                        Some(message) => self.handle_message(message).await,
                        None => {
                            log::trace!("RequestReceiver: Stopping since channel closed");
                            break;
                        },
                    }
                },
            }
        }
        shutdown.recv_timeout().await;
        log::debug!("RequestReceiver: Exiting");
    }
}

struct FragmentedMessageReceiver {
    received_buffer: ReceivedMessagesBuffer,
    mixnet_packet_receiver: MixnetMessageReceiver,
}

impl FragmentedMessageReceiver {
    fn new(
        received_buffer: ReceivedMessagesBuffer,
        mixnet_packet_receiver: MixnetMessageReceiver,
    ) -> Self {
        FragmentedMessageReceiver {
            received_buffer,
            mixnet_packet_receiver,
        }
    }

    async fn run_with_shutdown(&mut self, mut shutdown: task::ShutdownListener) {
        debug!("Started FragmentedMessageReceiver with graceful shutdown support");
        while !shutdown.is_shutdown() {
            tokio::select! {
                new_messages = self.mixnet_packet_receiver.next() => match new_messages {
                    Some(new_messages) => {
                        self.received_buffer.handle_new_received(new_messages).await;
                    }
                    None => {
                        log::trace!("FragmentedMessageReceiver: Stopping since channel closed");
                        break;
                    }
                },
                _ = shutdown.recv() => {
                    log::trace!("FragmentedMessageReceiver: Received shutdown");
                }
            }
        }
        shutdown.recv_timeout().await;
        log::debug!("FragmentedMessageReceiver: Exiting");
    }
}

pub(crate) struct ReceivedMessagesBufferController {
    fragmented_message_receiver: FragmentedMessageReceiver,
    request_receiver: RequestReceiver,
}

impl ReceivedMessagesBufferController {
    pub(crate) fn new(
        local_encryption_keypair: Arc<encryption::KeyPair>,
        query_receiver: ReceivedBufferRequestReceiver,
        mixnet_packet_receiver: MixnetMessageReceiver,
        reply_key_storage: SentReplyKeys,
        reply_controller_sender: ReplyControllerSender,
    ) -> Self {
        let received_buffer = ReceivedMessagesBuffer::new(
            local_encryption_keypair,
            reply_key_storage,
            reply_controller_sender,
        );

        ReceivedMessagesBufferController {
            fragmented_message_receiver: FragmentedMessageReceiver::new(
                received_buffer.clone(),
                mixnet_packet_receiver,
            ),
            request_receiver: RequestReceiver::new(received_buffer, query_receiver),
        }
    }

    pub fn start_with_shutdown(self, shutdown: task::ShutdownListener) {
        let mut fragmented_message_receiver = self.fragmented_message_receiver;
        let mut request_receiver = self.request_receiver;

        let shutdown_handle = shutdown.clone();
        spawn_future(async move {
            fragmented_message_receiver
                .run_with_shutdown(shutdown_handle)
                .await;
        });
        spawn_future(async move {
            request_receiver.run_with_shutdown(shutdown).await;
        });
    }
}
