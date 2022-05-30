// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen
use crate::{
    error::P2pError,
    event,
    message::{self, Message, MessageType, PubSubMessage},
    net::{self, NetworkingService, PubSubService},
};
use chainstate::{chainstate_interface, BlockError, ChainstateError::ProcessBlockError};
use common::chain::ChainConfig;
use futures::FutureExt;
use logging::log;
use std::sync::Arc;
use tokio::sync::mpsc;

// TODO: figure out proper channel sizes
const CHANNEL_SIZE: usize = 64;

pub struct PubSubMessageHandler<T>
where
    T: NetworkingService,
{
    config: Arc<ChainConfig>,
    pubsub_handle: T::PubSubHandle,
    chainstate_handle: subsystem::Handle<Box<dyn chainstate_interface::ChainstateInterface>>,
    rx_pubsub: mpsc::Receiver<event::PubSubControlEvent>,
}

impl<T> PubSubMessageHandler<T>
where
    T: NetworkingService,
    T::PubSubHandle: PubSubService<T>,
{
    pub fn new(
        config: Arc<ChainConfig>,
        pubsub_handle: T::PubSubHandle,
        chainstate_handle: subsystem::Handle<Box<dyn chainstate_interface::ChainstateInterface>>,
        rx_pubsub: mpsc::Receiver<event::PubSubControlEvent>,
    ) -> Self {
        Self {
            config,
            pubsub_handle,
            chainstate_handle,
            rx_pubsub,
        }
    }

    // TODO: remove one global message type and create multiple message types so we can get rid of this check
    async fn validate_pubsub_message(
        &mut self,
        event: net::PubSubEvent<T>,
    ) -> crate::Result<(T::PeerId, T::MessageId, PubSubMessage)> {
        match event {
            net::PubSubEvent::MessageReceived {
                peer_id,
                message_id,
                message:
                    Message {
                        magic: _,
                        msg: MessageType::PubSub(PubSubMessage::Block(block)),
                    },
            } => Ok((peer_id, message_id, PubSubMessage::Block(block))),
            net::PubSubEvent::MessageReceived {
                peer_id,
                message_id,
                message:
                    Message {
                        magic: _,
                        msg: MessageType::Syncing(_),
                    },
            } => {
                // TODO: report misbehaviour to swarm manager
                log::error!("received an invalid message from peer {:?}", peer_id);
                self.pubsub_handle
                    .report_validation_result(peer_id, message_id, net::ValidationResult::Reject)
                    .await?;
                Err(P2pError::InvalidData)
            }
        }
    }

    // while initial block download is in progress, ignore all incoming data
    // and wait for the completion event to be received from syncing
    async fn node_syncing(&mut self) -> crate::Result<()> {
        loop {
            tokio::select! {
                event = self.pubsub_handle.poll_next() => {
                    let (peer_id, message_id, _) = self.validate_pubsub_message(event?).await?;

                    log::trace!(
                        "received a pubsub message from peer {:?}, ignoring",
                        peer_id
                    );

                    self.pubsub_handle
                        .report_validation_result(
                            peer_id,
                            message_id,
                            net::ValidationResult::Ignore,
                        )
                        .await?;
                }
                event = self.rx_pubsub.recv().fuse() => match event.ok_or(P2pError::ChannelClosed)? {
                    event::PubSubControlEvent::InitialBlockDownloadDone => {
                        log::info!("initial block download done, activate pubsub");
                        return Ok(());
                    }
                }
            }
        }
    }

    async fn node_active(&mut self) -> crate::Result<()> {
        let (tx, mut rx) = mpsc::channel(CHANNEL_SIZE);

        let subscribe_func =
            Arc::new(
                move |chainstate_event: chainstate::ChainstateEvent| match chainstate_event {
                    chainstate::ChainstateEvent::NewTip(block_id, _) => {
                        futures::executor::block_on(async {
                            if let Err(e) = tx.send(block_id).await {
                                log::error!("pubsub manager closed: {:?}", e)
                            }
                        });
                    }
                },
            );

        self.chainstate_handle
            .call_mut(|this| this.subscribe_to_events(subscribe_func))
            .await
            .map_err(|_| P2pError::SubsystemFailure)?;

        loop {
            tokio::select! {
                event = self.pubsub_handle.poll_next() => {
                    let (peer_id, message_id, message) = self.validate_pubsub_message(event?).await?;

                    log::trace!(
                        "received a pubsub message from peer {:?}, send to chainstate",
                        peer_id
                    );

                    match message {
                        PubSubMessage::Block(block) => {
                            let result = match self
                                .chainstate_handle
                                .call_mut(move |this| {
                                    this.process_block(block, chainstate::BlockSource::Peer)
                                })
                                .await?
                            {
                                Ok(_) => net::ValidationResult::Accept,
                                Err(ProcessBlockError(BlockError::BlockAlreadyExists(_id))) =>
                                    net::ValidationResult::Accept, // TODO: ignore?
                                Err(err) => {
                                    // TODO: report misbehaviour to swarm manager and close connection
                                    log::error!(
                                    "block rejected, peer id {:?}, message id {:?}, reason, {:?}",
                                    peer_id,
                                    message_id,
                                    err
                                );

                                net::ValidationResult::Reject
                                }
                            };
                            self.pubsub_handle
                                .report_validation_result(peer_id, message_id, result)
                                .await?;
                        }
                    }
                }
                block_id = rx.recv().fuse() => {
                    let block_id = block_id.ok_or(P2pError::ChannelClosed)?;
                    let block = self
                        .chainstate_handle
                        .call(|this| this.get_block(block_id))
                        .await??;

                    // TODO: make this look nicer
                    match block {
                        Some(block) => {
                            match self.pubsub_handle
                                .publish(message::Message {
                                    magic: *self.config.magic_bytes(),
                                    msg: message::MessageType::PubSub(
                                        message::PubSubMessage::Block(block),
                                    ),
                                })
                                .await {
                                    Ok(_) => {},
                                    Err(P2pError::ChannelClosed) => return Err(P2pError::ChannelClosed),
                                    Err(e) => {
                                        log::error!("failed to publish message: {:?}", e);
                                    }
                                }
                        }
                        None => {
                            log::error!("CRITICAL: best block not available")
                        }
                    }
                }
            }
        }
    }

    pub async fn run(&mut self) -> crate::Result<()> {
        // when node is started and it connects to some peers,
        // it starts the initial block download. During this period,
        // all events from both syncing and pubsub implementation should be ignored
        self.node_syncing().await?;

        // when the initial block download is done, SyncManager notifies us about it,
        // meaning the PubSubMessageHandler can start processing block/transaction announcements
        self.node_active().await
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn it_works() {
        assert_eq!(1 + 1, 2);
    }
}
