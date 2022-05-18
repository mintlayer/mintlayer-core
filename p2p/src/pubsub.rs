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
#![allow(unused)]

use crate::{
    error::{self, P2pError},
    event,
    message::{self, Message, MessageType, PubSubMessage},
    net::{self, NetworkingService, PubSubService},
};
use common::chain::ChainConfig;
use common::primitives::Idable;
use consensus::consensus_interface;
use futures::FutureExt;
use logging::log;
use std::sync::Arc;
use tokio::sync::mpsc;

// TODO: figure out proper channel sizes
const CHANNEL_SIZE: usize = 64;

pub struct PubSubManager<T>
where
    T: NetworkingService,
{
    handle: T::PubSubHandle,
    consensus_handle: subsystem::Handle<Box<dyn consensus_interface::ConsensusInterface>>,
}

impl<T> PubSubManager<T>
where
    T: NetworkingService,
    T::PubSubHandle: PubSubService<T>,
{
    pub fn new(
        handle: T::PubSubHandle,
        consensus_handle: subsystem::Handle<Box<dyn consensus_interface::ConsensusInterface>>,
    ) -> Self {
        Self {
            handle,
            consensus_handle,
        }
    }

    pub async fn on_pubsub_event(&mut self, event: net::PubSubEvent<T>) -> error::Result<()> {
        // TODO: remove one global message type and create multiple message types
        match event {
            net::PubSubEvent::MessageReceived {
                peer_id,
                message_id,
                message:
                    Message {
                        magic,
                        msg: MessageType::PubSub(PubSubMessage::Block(block)),
                    },
            } => {
                let result = match self
                    .consensus_handle
                    .call_mut(move |this| this.process_block(block, consensus::BlockSource::Peer))
                    .await?
                {
                    Ok(_) => net::ValidationResult::Accept,
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

                return self.handle.report_validation_result(peer_id, message_id, result).await;
            }
            net::PubSubEvent::MessageReceived {
                peer_id,
                message_id: _,
                message:
                    Message {
                        magic: _,
                        msg: MessageType::Syncing(_),
                    },
            } => {
                // TODO: ban peer
                log::error!("peer {:?} sent syncing message through pubsub", peer_id);
                Ok(())
            }
        }
    }

    pub async fn run(&mut self) -> error::Result<()> {
        let (tx, mut rx) = mpsc::channel(CHANNEL_SIZE);
        let config = common::chain::config::create_mainnet();

        let subscribe_func =
            Arc::new(
                move |consensus_event: consensus::ConsensusEvent| match consensus_event {
                    consensus::ConsensusEvent::NewTip(block_id, _) => {
                        futures::executor::block_on(async {
                            if let Err(e) = tx.send(block_id).await {
                                log::error!("pubsub manager closed: {:?}", e)
                            }
                        });
                    }
                },
            );

        self.consensus_handle
            .call_mut(|this| this.subscribe_to_events(subscribe_func))
            .await
            .map_err(|_| P2pError::SubsystemFailure)?;

        loop {
            tokio::select! {
                event = self.handle.poll_next() => {
                    self.on_pubsub_event(event?).await?;
                }
                block_id = rx.recv().fuse() => {
                    let block_id = block_id.ok_or(P2pError::ChannelClosed)?;
                    let block = self
                        .consensus_handle
                        .call(|this| this.get_block(block_id))
                        .await??;

                    match block {
                        Some(block) => {
                            self.handle
                                .publish(message::Message {
                                    magic: *config.magic_bytes(),
                                    msg: message::MessageType::PubSub(
                                        message::PubSubMessage::Block(block),
                                    ),
                                })
                                .await?;
                        }
                        None => {
                            log::error!("CRITICAL: best block not available")
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn it_works() {
        assert_eq!(1 + 1, 2);
    }
}
