// Copyright (c) 2023 RBB S.r.l
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
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use common::chain::ChainConfig;
use crypto::random::Rng;
use p2p::types::peer_id::PeerId;

use crate::crawler_p2p::crawler::{
    address_data::AddressState, Crawler, CrawlerCommand, CrawlerEvent,
};

/// Mock crawler
pub struct MockCrawler {
    pub crawler: Crawler<SocketAddr>,
    pub chain_config: Arc<ChainConfig>,
    pub address_updates: Vec<AddressUpdate>,
    pub connect_requests: Vec<SocketAddr>,
    pub reachable: BTreeSet<SocketAddr>,
    pub persistent: BTreeSet<SocketAddr>,
    pub pending_connects: BTreeSet<SocketAddr>,
    pub pending_disconnects: BTreeSet<PeerId>,
    pub peers: BTreeMap<PeerId, MockPeer>,
    pub peer_addresses: BTreeMap<SocketAddr, PeerId>,
}

#[derive(Debug)]
pub struct MockPeer {
    address: SocketAddr,
    is_compatible: bool,
}

#[derive(Debug)]
pub struct AddressUpdate {
    pub address: SocketAddr,
    pub old_state: AddressState,
    pub new_state: AddressState,
}

pub fn test_crawler(
    loaded_addresses: BTreeSet<SocketAddr>,
    added_addresses: BTreeSet<SocketAddr>,
) -> MockCrawler {
    let chain_config = Arc::new(common::chain::config::create_mainnet());

    let crawler = Crawler::new(
        chain_config.clone(),
        loaded_addresses.clone(),
        added_addresses,
    );

    MockCrawler {
        crawler,
        chain_config,
        address_updates: Default::default(),
        connect_requests: Default::default(),
        reachable: Default::default(),
        persistent: loaded_addresses.iter().cloned().collect(),
        pending_connects: Default::default(),
        pending_disconnects: Default::default(),
        peers: Default::default(),
        peer_addresses: BTreeMap::new(),
    }
}

impl MockCrawler {
    pub fn timer(&mut self, period: Duration, rng: &mut impl Rng) {
        self.step(CrawlerEvent::Timer { period }, rng);
    }

    pub fn step(&mut self, event: CrawlerEvent<SocketAddr>, rng: &mut impl Rng) {
        match &event {
            CrawlerEvent::Timer { period: _ } => {}
            CrawlerEvent::NewAddress {
                address: _,
                sender: _,
            } => {}
            CrawlerEvent::Connected { peer_info, address } => {
                let removed = self.pending_connects.remove(address);
                assert!(removed);

                let mock_peer = MockPeer {
                    address: *address,
                    is_compatible: peer_info.is_compatible(&self.chain_config),
                };
                let old_peer = self.peers.insert(peer_info.peer_id, mock_peer);
                assert!(old_peer.is_none());

                let old_peer = self.peer_addresses.insert(*address, peer_info.peer_id);
                assert!(old_peer.is_none());
            }
            CrawlerEvent::Disconnected { peer_id } => {
                let old_peer = self.peers.remove(peer_id).unwrap();

                self.peer_addresses.remove(&old_peer.address).unwrap();

                // If the remote peer initiated the disconnect, then `pending_disconnects` won't have this peer_id
                let _removed = self.pending_disconnects.remove(peer_id);
            }
            CrawlerEvent::ConnectionError { address, error: _ } => {
                let removed = self.pending_connects.remove(address);
                assert!(removed);
            }
        }

        let mut cmd_handler = |cmd| match cmd {
            CrawlerCommand::Connect { address } => {
                let inserted = self.pending_connects.insert(address);
                assert!(inserted);
                self.connect_requests.push(address);
            }
            CrawlerCommand::Disconnect { peer_id } => {
                let inserted = self.pending_disconnects.insert(peer_id);
                assert!(inserted);
            }
            CrawlerCommand::UpdateAddress {
                address,
                old_state,
                new_state,
            } => {
                match (old_state.is_reachable(), new_state.is_reachable()) {
                    (false, true) => {
                        let inserted = self.reachable.insert(address);
                        assert!(inserted);
                    }
                    (true, false) => {
                        let removed = self.reachable.remove(&address);
                        assert!(removed);
                    }
                    _ => {}
                }

                match (old_state.is_persistent(), new_state.is_persistent()) {
                    (false, true) => {
                        let inserted = self.persistent.insert(address);
                        assert!(inserted);
                    }
                    (true, false) => {
                        let inserted = self.persistent.remove(&address);
                        assert!(inserted);
                    }
                    _ => {}
                }

                self.address_updates.push(AddressUpdate {
                    address,
                    old_state,
                    new_state,
                });
            }
        };

        self.crawler.step(event, &mut cmd_handler, rng);

        // Check invariants after every step

        // Verify that all reachable nodes are from compatible nodes
        for address in self.reachable.iter() {
            let peer_id = self.peer_addresses.get(address).unwrap();
            let peer = self.peers.get(peer_id).unwrap();
            assert!(peer.is_compatible);
        }

        // Verify that all compatible nodes are reachable
        for peer in self.peers.values() {
            let valid_ip = peer.is_compatible;
            assert_eq!(self.reachable.contains(&peer.address), valid_ip);
        }
    }
}
