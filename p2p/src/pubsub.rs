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
    net::{self, NetworkService, PubSubService},
};
use common::chain::ChainConfig;
use common::primitives::Idable;
use futures::FutureExt;
use logging::log;
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct PubSubManager<T>
where
    T: NetworkService,
{
    handle: T::PubSubHandle,
    consensus: subsystem::Handle<consensus::ConsensusInterface>,
}

impl<T> PubSubManager<T>
where
    T: NetworkService,
    T::PubSubHandle: PubSubService<T>,
{
    pub fn new(
        handle: T::PubSubHandle,
        consensus: subsystem::Handle<consensus::ConsensusInterface>,
    ) -> Self {
        Self { handle, consensus }
    }

    pub async fn on_floodsub_event(&mut self, event: net::PubSubEvent<T>) -> error::Result<()> {
        // TODO: use `ensure!()` to check all values
        if let net::PubSubEvent::MessageReceived {
            peer_id,
            message_id,
            message:
                Message {
                    magic,
                    msg: MessageType::PubSub(PubSubMessage::Block(block)),
                },
        } = event
        {
            let result = match self
                .consensus
                .call_mut(move |this| this.process_block(block, consensus::BlockSource::Peer(1337)))
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

        // TODO: handle unexpected message
        todo!();
    }

    pub async fn run(&mut self) -> error::Result<()> {
        // TODO: channel size
        let (tx, mut rx) = mpsc::channel(16);
        let config = common::chain::config::create_mainnet();

        let subscribe_func =
            Arc::new(
                move |consensus_event: consensus::ConsensusEvent| match consensus_event {
                    consensus::ConsensusEvent::NewTip(block_id, _) => {
                        futures::executor::block_on(async {
                            tx.send(block_id).await.unwrap();
                        });
                    }
                },
            );

        self.consensus
            .call_mut(move |this| this.subscribe_to_events(subscribe_func))
            .await
            .unwrap();

        loop {
            tokio::select! {
                event = self.handle.poll_next() => {
                    self.on_floodsub_event(event?).await?;
                }
                block_id = rx.recv().fuse() => {
                    let block_id = block_id.ok_or(P2pError::ChannelClosed)?;
                    let block = match self
                        .consensus
                        .call_mut(move |this| {
                            this.get_block(block_id)
                        })
                        .await
                    {
                        Ok(Ok(Some(block))) => block,
                        _ => {
                            // TODO: what to do here?
                            log::error!("error occurred with trying to get best block");
                            return Err(P2pError::InvalidData);
                        }
                    };

                    self.handle.publish(message::Message {
                        magic: *config.magic_bytes(),
                        msg: message::MessageType::PubSub(message::PubSubMessage::Block(block))
                    }).await?;
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
