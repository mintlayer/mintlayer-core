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

//! Publish-subscribe message/event handling

use crate::{
    error::{P2pError, ProtocolError, PublishError},
    event,
    message::{self, Message, MessageType, PubSubMessage},
    net::{
        types::{PubSubEvent, PubSubTopic, ValidationResult},
        NetworkingService, PubSubService,
    },
};
use chainstate::{
    ban_score::BanScore,
    chainstate_interface, BlockError,
    ChainstateError::{FailedToInitializeChainstate, FailedToReadProperty, ProcessBlockError},
};
use common::{
    chain::{block::Block, ChainConfig},
    primitives::Id,
};
use futures::FutureExt;
use logging::log;
use std::sync::Arc;
use tokio::sync::mpsc;

// TODO: figure out proper channel sizes
const CHANNEL_SIZE: usize = 64;

/// Publish-subscribe message handler
pub struct PubSubMessageHandler<T: NetworkingService> {
    /// Chain config
    chain_config: Arc<ChainConfig>,

    /// Handle for communication with networking service
    pubsub_handle: T::PubSubHandle,

    /// Handle for communication with chainstate
    chainstate_handle: subsystem::Handle<Box<dyn chainstate_interface::ChainstateInterface>>,

    /// RX channel for receiving control events from RPC/[`swarm::PeerManager`]
    rx_pubsub: mpsc::Receiver<event::PubSubControlEvent>,

    /// Topics that the `PubSubMessageHandler` listens to
    topics: Vec<PubSubTopic>,
}

impl<T> PubSubMessageHandler<T>
where
    T: NetworkingService,
    T::PubSubHandle: PubSubService<T>,
{
    /// Create new `PubSubMessageHandler`
    ///
    /// # Arguments
    /// * `chain_config` - chain configuration
    /// * `pubsub_handle` - handle for communication with networking service
    /// * `chainstate_handle` -  handle for communication with chainstate
    /// * `rx_pubsub` - RX channel for receiving control events
    pub fn new(
        chain_config: Arc<ChainConfig>,
        pubsub_handle: T::PubSubHandle,
        chainstate_handle: subsystem::Handle<Box<dyn chainstate_interface::ChainstateInterface>>,
        rx_pubsub: mpsc::Receiver<event::PubSubControlEvent>,
        topics: &[PubSubTopic],
    ) -> Self {
        Self {
            chain_config,
            pubsub_handle,
            chainstate_handle,
            rx_pubsub,
            topics: topics.to_vec(),
        }
    }

    /// Subscribe to events
    async fn subscribe_to_events(&mut self) -> crate::Result<mpsc::Receiver<Id<Block>>> {
        let (tx, rx) = mpsc::channel(CHANNEL_SIZE);

        let subscribe_func =
            Arc::new(
                move |chainstate_event: chainstate::ChainstateEvent| match chainstate_event {
                    chainstate::ChainstateEvent::NewTip(block_id, _) => {
                        futures::executor::block_on(async {
                            if let Err(e) = tx.send(block_id).await {
                                log::error!("PubSubMessageHandler closed: {:?}", e)
                            }
                        });
                    }
                },
            );

        self.chainstate_handle
            .call_mut(|this| this.subscribe_to_events(subscribe_func))
            .await
            .map_err(|_| P2pError::SubsystemFailure)?;

        self.pubsub_handle.subscribe(&self.topics).await?;
        Ok(rx)
    }

    /// Process block announcement from the network
    async fn process_block_announcement(
        &mut self,
        peer_id: T::PeerId,
        message_id: T::MessageId,
        block: Block,
    ) -> crate::Result<()> {
        let result = match self
            .chainstate_handle
            .call(move |this| this.preliminary_block_check(block))
            .await?
        {
            Ok(block) => {
                self.chainstate_handle
                    .call_mut(move |this| this.process_block(block, chainstate::BlockSource::Peer))
                    .await?
            }
            Err(err) => Err(err),
        };

        let (validation_result, score) = match result {
            Ok(_) => (ValidationResult::Accept, 0),
            Err(ProcessBlockError(ref block_error)) => match block_error {
                err @ BlockError::BlockAlreadyExists(_id) => {
                    (ValidationResult::Accept, err.ban_score())
                }
                err @ BlockError::StorageError(_) => (ValidationResult::Ignore, err.ban_score()),
                err @ BlockError::BestBlockLoadError(_) => {
                    (ValidationResult::Ignore, err.ban_score())
                }
                err @ BlockError::InvariantErrorFailedToFindNewChainPath(_, _, _) => {
                    (ValidationResult::Ignore, err.ban_score())
                }
                err @ BlockError::InvariantErrorInvalidTip => {
                    (ValidationResult::Ignore, err.ban_score())
                }
                err @ BlockError::InvariantErrorPrevBlockNotFound => {
                    (ValidationResult::Ignore, err.ban_score())
                }
                err @ BlockError::DatabaseCommitError(_, _, _) => {
                    (ValidationResult::Ignore, err.ban_score())
                }
                err @ BlockError::OrphanCheckFailed(_err) => {
                    (ValidationResult::Ignore, err.ban_score())
                }
                err @ BlockError::CheckBlockFailed(_err) => {
                    (ValidationResult::Reject, err.ban_score())
                }
                err @ BlockError::StateUpdateFailed(_err) => {
                    (ValidationResult::Ignore, err.ban_score())
                }
                err @ BlockError::PrevBlockNotFound => (ValidationResult::Reject, err.ban_score()),
                err @ BlockError::InvalidBlockSource => (ValidationResult::Reject, err.ban_score()),
                err @ BlockError::BlockProofCalculationError(_) => {
                    (ValidationResult::Reject, err.ban_score())
                }
            },
            Err(FailedToInitializeChainstate(_)) => (ValidationResult::Ignore, 0),
            Err(FailedToReadProperty(_)) => (ValidationResult::Ignore, 0),
        };

        if score > 0 {
            // TODO: adjust peer score
        }

        self.pubsub_handle
            .report_validation_result(peer_id, message_id, validation_result)
            .await
    }

    /// Announce block to the network
    async fn announce_block(&mut self, block: Block) -> crate::Result<()> {
        let result = self
            .pubsub_handle
            .publish(message::Message {
                magic: *self.chain_config.magic_bytes(),
                msg: message::MessageType::PubSub(message::PubSubMessage::Block(block)),
            })
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(P2pError::ChannelClosed) => result,
            Err(P2pError::PublishError(ref error)) => match error {
                PublishError::InsufficientPeers => Ok(()),
                PublishError::TransformFailed => result,
                PublishError::Duplicate => result,
                PublishError::MessageTooLarge(_size, _limit) => result,
                PublishError::SigningFailed => result,
            },
            Err(P2pError::ProtocolError(ProtocolError::InvalidMessage)) => result,
            Err(err) => {
                log::error!(
                    "Unexpected error occurred while trying to announce block: {}",
                    err
                );
                Ok(())
            }
        }
    }

    /// Run `PubSubMessageHandler` event loop
    pub async fn run(&mut self) -> crate::Result<void::Void> {
        match self.rx_pubsub.recv().await {
            None => return Err(P2pError::ChannelClosed),
            Some(event::PubSubControlEvent::InitialBlockDownloadDone) => {
                log::info!("Initial block download done, starting PubSubMessageHandler");
            }
        }

        // subscribe to chainstate events and pubsub topics
        let mut block_rx = self.subscribe_to_events().await?;

        loop {
            tokio::select! {
                event = self.pubsub_handle.poll_next() => match event? {
                    PubSubEvent::MessageReceived { peer_id, message_id, message } => match message {
                        Message {
                            magic: _,
                            msg: MessageType::PubSub(PubSubMessage::Block(block)),
                        } => self.process_block_announcement(peer_id, message_id, block).await?,
                        Message {
                            magic: _,
                           msg: MessageType::Syncing(_),
                        } => {
                            // TODO: ban peer
                        }
                    }
                },
                block_id = block_rx.recv().fuse() => {
                    let block_id = block_id.ok_or(P2pError::ChannelClosed)?;

                    match self.chainstate_handle.call(|this| this.get_block(block_id)).await?? {
                        Some(block) => self.announce_block(block).await?,
                        None => log::error!("CRITICAL: best block not available"),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn it_works() {
        assert_eq!(1 + 1, 2);
    }
}
