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
    sync::Arc,
    time::Duration,
};

use common::{chain::ChainConfig, primitives::time::Time};
use p2p::types::{
    bannable_address::BannableAddress, peer_id::PeerId, socket_address::SocketAddress,
};
use randomness::Rng;

use crate::crawler_p2p::{
    crawler::{address_data::AddressState, Crawler, CrawlerCommand, CrawlerConfig, CrawlerEvent},
    crawler_manager::storage::AddressInfo,
};

/// Mock crawler
pub struct MockCrawler {
    pub crawler: Crawler,
    pub chain_config: Arc<ChainConfig>,
    pub address_updates: Vec<AddressUpdate>,
    pub connect_requests: Vec<SocketAddress>,
    pub reachable: BTreeSet<SocketAddress>,
    pub persistent: BTreeSet<SocketAddress>,
    pub pending_connects: BTreeSet<SocketAddress>,
    pub pending_disconnects: BTreeSet<PeerId>,
    pub peers: BTreeMap<PeerId, MockPeer>,
    pub peer_addresses: BTreeMap<SocketAddress, PeerId>,
    pub banned_addresses: BTreeMap<BannableAddress, Time>,
    pub address_requests: BTreeMap<PeerId, usize>,
}

#[derive(Debug)]
pub struct MockPeer {
    address: SocketAddress,
    is_compatible: bool,
}

#[derive(Debug)]
pub struct AddressUpdate {
    pub address: SocketAddress,
    pub old_state: AddressState,
    pub new_state: AddressState,
}

pub fn test_crawler(
    config: CrawlerConfig,
    loaded_addresses: BTreeMap<SocketAddress, AddressInfo>,
    loaded_banned_addresses: BTreeMap<BannableAddress, Time>,
    reserved_addresses: BTreeSet<SocketAddress>,
    now: Time,
) -> MockCrawler {
    let chain_config = Arc::new(common::chain::config::create_mainnet());

    let crawler = Crawler::new(
        now,
        chain_config.clone(),
        config,
        loaded_addresses.clone(),
        loaded_banned_addresses.clone(),
        reserved_addresses,
    );

    MockCrawler {
        crawler,
        chain_config,
        address_updates: Default::default(),
        connect_requests: Default::default(),
        reachable: Default::default(),
        persistent: loaded_addresses.keys().cloned().collect(),
        pending_connects: Default::default(),
        pending_disconnects: Default::default(),
        peers: Default::default(),
        peer_addresses: BTreeMap::new(),
        banned_addresses: loaded_banned_addresses,
        address_requests: BTreeMap::new(),
    }
}

impl MockCrawler {
    pub fn timer(&mut self, period: Duration, rng: &mut impl Rng) {
        self.step(CrawlerEvent::Timer { period }, rng);
    }

    pub fn step(&mut self, event: CrawlerEvent, rng: &mut impl Rng) {
        match &event {
            CrawlerEvent::Timer { period: _ } => {}
            CrawlerEvent::AddressAnnouncement {
                address: _,
                sender: _,
            } => {}
            CrawlerEvent::AddressListResponse {
                addresses: _,
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
            CrawlerEvent::Misbehaved {
                peer_id: _,
                error: _,
            } => {}
            CrawlerEvent::MisbehavedOnHandshake {
                address: _,
                error: _,
            } => {}
        }

        let mut cmd_handler = |cmd| match cmd {
            CrawlerCommand::Connect { address } => {
                let inserted = self.pending_connects.insert(address);
                assert!(inserted);
                self.connect_requests.push(address);
            }
            CrawlerCommand::RequestAddresses { peer_id } => {
                *self.address_requests.entry(peer_id).or_insert(0) += 1;
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
            CrawlerCommand::MarkAsBanned { address, ban_until } => {
                self.banned_addresses.insert(address, ban_until);
            }
            CrawlerCommand::RemoveBannedStatus { address } => {
                self.banned_addresses.remove(&address);
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

        // Verify that all compatible nodes are reachable (unless they are being disconnected
        // at the moment) and all incompatible ones are non-reachable.
        for peer in self.peers.values() {
            let valid_ip = peer.is_compatible;
            let is_reachable = self.reachable.contains(&peer.address);
            let peer_id = self.peer_addresses.get(&peer.address).unwrap();
            let is_being_disconnected = self.pending_disconnects.contains(peer_id);

            if valid_ip {
                assert!(is_reachable || is_being_disconnected);
            } else {
                assert!(!is_reachable);
            }
        }
    }

    pub fn now(&self) -> Time {
        self.crawler.now
    }

    pub fn assert_banned_addresses(&self, expected: &[(BannableAddress, Time)]) {
        let expected: BTreeMap<_, _> = expected.iter().copied().collect();
        assert_eq!(self.banned_addresses, expected);
        assert_eq!(self.crawler.banned_addresses, expected);
    }

    pub fn assert_ban_scores(&self, expected: &[(PeerId, u32)]) {
        let expected: BTreeMap<_, _> = expected.iter().copied().collect();

        for (peer_id, peer) in &self.crawler.outbound_peers {
            assert_eq!(
                // "Compare" peer_id too, so that it appears in the message if the assertion fails.
                (*peer_id, peer.ban_score),
                (*peer_id, *expected.get(peer_id).unwrap_or(&0))
            );
        }
    }

    pub fn assert_pending_connects(&self, expected: &[SocketAddress]) {
        let expected: BTreeSet<_> = expected.iter().copied().collect();
        assert_eq!(self.pending_connects, expected);
    }

    pub fn assert_pending_disconnects(&self, expected: &[PeerId]) {
        let expected: BTreeSet<_> = expected.iter().copied().collect();
        assert_eq!(self.pending_disconnects, expected);
    }

    pub fn assert_connected_peers(&self, expected: &[PeerId]) {
        let expected: BTreeSet<_> = expected.iter().copied().collect();

        let actual1: BTreeSet<_> = self.peers.keys().copied().collect();
        assert_eq!(actual1, expected);

        let actual2: BTreeSet<_> = self.crawler.outbound_peers.keys().copied().collect();
        assert_eq!(actual2, expected);
    }

    pub fn assert_address_request_counts(&self, expected: &[(PeerId, usize)]) {
        let expected: BTreeMap<_, _> = expected.iter().copied().collect();
        assert_eq!(self.address_requests, expected);
    }
}
