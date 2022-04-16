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
use tokio::sync::mpsc;

// TODO: get TXs/blocks from the floodsub messages -> move error handling there

pub struct FloodsubManager<T>
where
    T: NetworkService,
{
    handle: T::FloodsubHandle,
    tx_sync: mpsc::Sender<event::SyncFloodEvent<T>>,
    rx_sync: mpsc::Receiver<event::BlockFloodEvent>,
}

impl<T> FloodsubManager<T>
where
    T: NetworkService,
    T::FloodsubHandle: FloodsubService<T>,
{
    pub fn new(
        handle: T::FloodsubHandle,
        tx_sync: mpsc::Sender<event::SyncFloodEvent<T>>,
        rx_sync: mpsc::Receiver<event::BlockFloodEvent>,
    ) -> Self {
        Self {
            handle,
            tx_sync,
            rx_sync,
        }
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

                if let MessageType::Syncing(SyncingMessage::Block { block }) = message.msg {
                    self.tx_sync.send(event::SyncFloodEvent::Block { peer_id, block }).await?;
                }
            }
        }

        Ok(())
    }

    pub async fn run(&mut self) -> error::Result<()> {
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
