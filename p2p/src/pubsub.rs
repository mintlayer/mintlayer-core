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
    message::{Message, MessageType, PubSubMessage},
    net::{self, NetworkService, PubSubService},
};
use common::{
    chain::{block::Block, ChainConfig},
    primitives::Idable,
};
use futures::FutureExt;
use logging::log;
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct PubSubManager<T>
where
    T: NetworkService,
{
    handle: T::PubSubHandle,
}

impl<T> PubSubManager<T>
where
    T: NetworkService,
    T::PubSubHandle: PubSubService<T>,
{
    pub fn new(handle: T::PubSubHandle) -> Self {
        Self { handle }
    }

    async fn is_valid_block(&mut self, block: Block) -> error::Result<bool> {
        // TODO: call consensus here and send it `block`
        // TODO: get response from consensus that tells whether the block was valid or not
        Ok(true)
    }

    async fn process_invalid_block(
        &mut self,
        peer_id: T::PeerId,
        message_id: T::MessageId,
    ) -> error::Result<()> {
        log::warn!("peer {:?} sent an invalid block (id {:?}), report ");

        self.handle
            .report_validation_result(peer_id, message_id, net::ValidationResult::Reject)
            .await?;

        self.swarm_handle
            .report_peer_behaviour(peer_id, swarm::PeerBehaviour::InvalidPubSubMessage)
            .await
    }

    pub async fn run(&mut self) -> error::Result<()> {
        // TODO: add receiver here which accepts function calls from other subsystems
        loop {
            tokio::select! {
                event = self.handle.poll_next() => {
                    let net::PubSubEvent::MessageReceived { peer_id, message_id, message } = event?;

                    log::debug!("received pubsub message from peer {:?}, message id {:?}", peer_id, message_id);

                    match message {
                        Message { msg: MessageType::PubSub(PubSubMessage::Block(block)), .. } => {
                            if !self.is_valid_block(block).await? {
                                return self.process_invalid_block(peer_id, message_id).await;
                            }

                            log::debug!(
                                "block with id {:?} from peer {:?} is valid, forward it to other peers",
                                message_id,
                                peer_id
                            );

                            self.handle
                                .report_validation_result(peer_id, message_id, net::ValidationResult::Accept)
                                .await
                        }
                        _ => self.process_invalid_block(peer_id, message_id).await?,
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
