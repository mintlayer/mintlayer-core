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
#![cfg(not(loom))]
#![allow(unused)]

use crate::{
    error::{self, P2pError},
    event,
    message::{MessageType, SyncingMessage},
    net::{self, FloodsubService, NetworkService},
};
use common::chain::ChainConfig;
use futures::FutureExt;
use logging::log;
use std::sync::Arc;

pub struct FloodsubManager<T>
where
    T: NetworkService,
{
    handle: T::FloodsubHandle,
}

impl<T> FloodsubManager<T>
where
    T: NetworkService,
    T::FloodsubHandle: FloodsubService<T>,
{
    pub fn new(handle: T::FloodsubHandle) -> Self {
        Self { handle }
    }

    pub async fn on_floodsub_event(&mut self, event: net::FloodsubEvent<T>) -> error::Result<()> {
        let net::FloodsubEvent::MessageReceived {
            peer_id,
            topic,
            message,
        } = event;

        match topic {
            net::FloodsubTopic::Transactions => {
                log::warn!("received new transaction: {:#?}", message);
            }
            net::FloodsubTopic::Blocks => {
                log::debug!(
                    "received new block ({:#?}) from peer {:?}",
                    message,
                    peer_id
                );

                // TODO: fix `FloodsubTopic::Blocks` to always contain a block!
                // TODO: add blk_handle + proc-macro2 handle type for it
                println!("received something ({:#?}) from {:?}", message, peer_id);
                todo!();

                // match message.msg {
                //     MessageType::Syncing(SyncingMessage::Block { block }) => {
                //         self.blk_handle.new_block(Arc::new(block)).await?;
                //     }
                //     _ => log::error!("invalid message received from peer {:?}", peer_id),
                // }
            }
        }

        Ok(())
    }

    async fn run(&mut self) -> error::Result<()> {
        // TODO: poll syncmanager for blocks
        // TODO: poll rpc for transactions

        loop {
            tokio::select! {
                event = self.handle.poll_next() => {
                    self.on_floodsub_event(event?).await?;
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
