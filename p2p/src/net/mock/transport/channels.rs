// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    collections::BTreeMap,
    fmt::{self, Display, Formatter},
};

use async_trait::async_trait;
use futures::{future, FutureExt};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::net::mock::{
    transport::{AddressMock, ConnectionMock, NetworkMock},
    types::{Message, MockPeerId},
};

pub struct ChannelNetworkMock {
    // TODO: FIXME: Fix the message type.
    peers: BTreeMap<MockPeerId, UnboundedReceiver<()>>,
}

impl ChannelNetworkMock {
    pub fn new() -> Self {
        Self {
            peers: BTreeMap::new(),
        }
    }

    async fn handle_peer_connection(&self, peer: MockPeerId, rx: &UnboundedReceiver<()>) {
        // TODO: FIXME:
        todo!();
    }
}

#[async_trait]
impl NetworkMock for ChannelNetworkMock {
    type Address = ChannelAddressMock;

    fn new(peers: usize) -> (Self, Vec<Self::Address>) {
        let (peers, addresses) = (0..peers)
            .map(|i| {
                let (tx, rx) = unbounded_channel();
                (
                    (MockPeerId::from_int(i as u64), rx),
                    ChannelAddressMock::new(tx),
                )
            })
            .unzip();
        (Self { peers }, addresses)
    }

    // fn add_peer(&mut self) -> Self::Address {
    //     let new_peer = MockPeerId::from_int(
    //         self.peers.keys().rev().next().map(|p| p.into_int() + 1).unwrap_or(0),
    //     );
    //     let (tx, rx) = unbounded_channel();
    //     assert!(self.peers.insert(new_peer, rx).is_none());
    //     ChannelAddressMock::new(tx)
    // }

    async fn run(self) {
        tokio::spawn(async move {
            let mut futures = self
                .peers
                .iter()
                .map(|(peer, rx)| self.handle_peer_connection(*peer, rx).boxed())
                .collect();
            loop {
                let (_, _, remaining) = future::select_all(futures).await;
                futures = remaining;
            }
        });
    }
}

#[derive(Clone, Debug)]
pub struct ChannelAddressMock {
    tx: UnboundedSender<()>,
}

impl ChannelAddressMock {
    pub fn new(tx: UnboundedSender<()>) -> Self {
        Self { tx }
    }
}

#[async_trait]
impl AddressMock for ChannelAddressMock {
    type Connection = ChannelConnectionMock;

    async fn create(self) -> Result<Self::Connection, ()> {
        todo!()
    }

    async fn connect(self) -> Result<Self::Connection, ()> {
        todo!()
    }
}

// TODO: FIXME:
impl Display for ChannelAddressMock {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

pub struct ChannelConnectionMock {
    tx: UnboundedSender<Message>,
    rx: UnboundedReceiver<Message>,
}

#[async_trait]
impl ConnectionMock for ChannelConnectionMock {
    async fn send(&mut self, message: Message) -> Result<(), ()> {
        // TODO: FIXME: Handle error.
        self.tx.send(message).unwrap();
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<Message>, ()> {
        Ok(self.rx.recv().await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn add_peer() {
    //     let mut network = ChannelNetworkMock::new();
    //     assert!(network.peers.is_empty());
    //
    //     network.add_peer();
    //     assert!(network.peers.contains_key(&MockPeerId::from_int(0)));
    //
    //     network.add_peer();
    //     assert!(network.peers.contains_key(&MockPeerId::from_int(1)));
    //
    //     network.add_peer();
    //     assert!(network.peers.contains_key(&MockPeerId::from_int(2)));
    // }
}
