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
    swarm,
};
use common::{
    chain::{block::Block, transaction::Transaction, ChainConfig},
    primitives::Idable,
};
use consensus::{BlockSource, ConsensusInterface};
use futures::FutureExt;
use logging::log;
use std::sync::Arc;
use subsystem::subsystem::{CallRequest, ShutdownRequest};
use tokio::sync::mpsc;

pub struct PubSubManager<T>
where
    T: NetworkService,
{
    pubsub: T::PubSubHandle,
    consensus: subsystem::Handle<ConsensusInterface>,
}

impl<T> PubSubManager<T>
where
    T: NetworkService + 'static,
    T::PubSubHandle: PubSubService<T>,
{
    pub fn new(pubsub: T::PubSubHandle, consensus: subsystem::Handle<ConsensusInterface>) -> Self {
        Self { pubsub, consensus }
    }

    async fn publish_block(&mut self, block: Block) -> error::Result<()> {
        self.pubsub.publish(Message {
            magic: [1, 2, 3, 4],
            msg: MessageType::PubSub(PubSubMessage::Block(block))
        })
        .await
    }

    async fn is_valid_block(&mut self, block: Block) -> error::Result<bool> {
        match self
            .consensus
            .call_mut(move |cons| cons.process_block(block, BlockSource::Local))
            .await
        {
            Ok(_) => {}
            Err(e) => {}
        };

        Ok(true)
    }

    async fn process_invalid_block(
        &mut self,
        peer_id: T::PeerId,
        message_id: T::MessageId,
    ) -> error::Result<()> {
        log::warn!(
            "peer {:?} sent an invalid block (message id {:?}), report ",
            peer_id,
            message_id
        );

        self.pubsub
            .report_validation_result(peer_id, message_id, net::ValidationResult::Reject)
            .await?;

        Ok(())
    }

    pub async fn run(&mut self, mut call_rq: CallRequest<Self>, mut shutdown_rq: ShutdownRequest) {
        loop {
            tokio::select! {
                event = self.pubsub.poll_next() => {
                    let net::PubSubEvent::MessageReceived { peer_id, message_id, message } = event.unwrap();

                    log::debug!("received pubsub message from peer {:?}, message id {:?}", peer_id, message_id);

                    match message {
                        Message { msg: MessageType::PubSub(PubSubMessage::Block(block)), .. } => {
                            if !self.is_valid_block(block).await.unwrap() {
                                self.process_invalid_block(peer_id, message_id).await.unwrap();
                            } else {

                            log::debug!(
                                "block with id {:?} from peer {:?} is valid, forward it to other peers",
                                message_id,
                                peer_id
                            );

                            self.pubsub
                                .report_validation_result(peer_id, message_id, net::ValidationResult::Accept)
                                .await.unwrap();
                            }
                        }
                        _ => self.process_invalid_block(peer_id, message_id).await.unwrap(),
                    }
                }
                call = call_rq.recv() => call(self).await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::libp2p::Libp2pService;
    use common::chain::config;

    // async fn make_pubsub_manager<T>(addr: T::Address) -> (PubSubManager<T>)
    async fn make_pubsub_manager<T>(addr: T::Address)
    where
        T: NetworkService + 'static,
        T::PubSubHandle: PubSubService<T>,
    {
        let config = Arc::new(config::create_mainnet());
        let (_, pubsub, _) = T::start(
            addr,
            &[],
            &[],
            Arc::clone(&config),
            std::time::Duration::from_secs(10),
        )
        .await
        .unwrap();

        let storage = blockchain_storage::Store::new_empty().unwrap();
        let manager = subsystem::Manager::new("mintlayer");
        let consensus = manager.start(
            "consensus",
            consensus::make_consensus(config::create_mainnet(), storage.clone()).unwrap(),
        );

        println!("create pubsub manager");
        let mut pubsub_mgr = PubSubManager::<T>::new(pubsub, consensus.clone());

        println!("start pubsub manager");
        let pubsub = manager.start_raw("pubsub", |call_rq, shut_rq| async move {
            pubsub_mgr.run(call_rq, shut_rq).await
        });

        println!("start main");
        manager.main().await

        // TODO: make ConsensusInterface and turn it into a subsystem
        // TODO: get consensus handle
        // TODO: create pubsubmanager and
        // todo!();
    }

    #[tokio::test]
    async fn it_maybe_works() {
        make_pubsub_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    }
}
