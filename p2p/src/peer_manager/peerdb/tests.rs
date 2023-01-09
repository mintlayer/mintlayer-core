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

use std::{sync::Arc, time::Duration};

use crate::{
    config::P2pConfig,
    net::{
        mock::{
            transport::{MockChannelTransport, NoiseTcpTransport, TcpTransportSocket},
            types::MockPeerId,
            MockService,
        },
        types::{PeerInfo, PubSubTopic, Role},
        AsBannableAddress, NetworkingService,
    },
    peer_manager::{peerdb::PeerDb, tests::default_protocols},
    testing_utils::{RandomAddressMaker, TestChannelAddressMaker, TestTcpAddressMaker},
};

fn make_peer_info<S, A>() -> (S::PeerId, S::Address, PeerInfo<S>)
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let peer_id = MockPeerId::new();

    (
        peer_id,
        A::new(),
        PeerInfo::<S> {
            peer_id,
            magic_bytes: [1, 2, 3, 4],
            version: common::primitives::semver::SemVer::new(0, 1, 0),
            agent: None,
            protocols: default_protocols(),
            subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions].into_iter().collect(),
        },
    )
}

fn add_active_peer<S, A>(peerdb: &mut PeerDb<S>) -> S::PeerId
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let (peer_id, address, info) = make_peer_info::<S, A>();
    peerdb.peer_connected(address, Role::Inbound, info);
    peer_id
}

fn adjust_peer_score_normal_threshold<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default())).unwrap();

    let peer_id = add_active_peer::<S, A>(&mut peerdb);
    let address = peerdb.peers.get(&peer_id).unwrap().address.as_bannable();
    assert!(peerdb.adjust_peer_score(&peer_id, 100));
    assert!(peerdb.is_address_banned(&address));
}

#[test]
fn adjust_peer_score_normal_threshold_mock_tcp() {
    adjust_peer_score_normal_threshold::<MockService<TcpTransportSocket>, TestTcpAddressMaker>();
}

#[test]
fn adjust_peer_score_normal_threshold_mock_channels() {
    adjust_peer_score_normal_threshold::<MockService<MockChannelTransport>, TestChannelAddressMaker>(
    );
}

#[test]
fn adjust_peer_score_normal_threshold_mock_noise() {
    adjust_peer_score_normal_threshold::<MockService<NoiseTcpTransport>, TestTcpAddressMaker>();
}

fn adjust_peer_score_higher_threshold<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let config = P2pConfig {
        bind_address: Default::default(),
        add_node: Default::default(),
        ban_threshold: 200.into(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        mdns_config: Default::default(),
        node_type: Default::default(),
    };
    let mut peerdb = PeerDb::<S>::new(Arc::new(config)).unwrap();

    let peer_id = add_active_peer::<S, A>(&mut peerdb);
    assert!(!peerdb.adjust_peer_score(&peer_id, 100));

    let address = peerdb.peers.get(&peer_id).unwrap().address.as_bannable();
    assert!(!peerdb.is_address_banned(&address));
}

#[test]
fn adjust_peer_score_higher_threshold_mock_tcp() {
    adjust_peer_score_higher_threshold::<MockService<TcpTransportSocket>, TestTcpAddressMaker>();
}

#[test]
fn adjust_peer_score_higher_threshold_mock_channels() {
    adjust_peer_score_higher_threshold::<MockService<MockChannelTransport>, TestChannelAddressMaker>(
    );
}

#[test]
fn adjust_peer_score_higher_threshold_mock_noise() {
    adjust_peer_score_higher_threshold::<MockService<NoiseTcpTransport>, TestTcpAddressMaker>();
}

fn adjust_peer_score_lower_threshold<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let config = P2pConfig {
        bind_address: Default::default(),
        add_node: Default::default(),
        ban_threshold: 20.into(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        mdns_config: Default::default(),
        node_type: Default::default(),
    };
    let mut peerdb = PeerDb::<S>::new(Arc::new(config)).unwrap();

    let peer_id = add_active_peer::<S, A>(&mut peerdb);
    let address = peerdb.peers.get(&peer_id).unwrap().address.as_bannable();
    assert!(peerdb.adjust_peer_score(&peer_id, 30));
    assert!(peerdb.is_address_banned(&address));
}

#[test]
fn adjust_peer_score_lower_threshold_mock_tcp() {
    adjust_peer_score_lower_threshold::<MockService<TcpTransportSocket>, TestTcpAddressMaker>();
}

#[test]
fn adjust_peer_score_lower_threshold_mock_channels() {
    adjust_peer_score_lower_threshold::<MockService<MockChannelTransport>, TestChannelAddressMaker>(
    );
}

#[test]
fn adjust_peer_score_lower_threshold_mock_noise() {
    adjust_peer_score_lower_threshold::<MockService<NoiseTcpTransport>, TestTcpAddressMaker>();
}

async fn unban_peer<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig {
        bind_address: Default::default(),
        add_node: Default::default(),
        ban_threshold: Default::default(),
        ban_duration: Duration::from_secs(2).into(),
        outbound_connection_timeout: Default::default(),
        mdns_config: Default::default(),
        node_type: Default::default(),
    }))
    .unwrap();

    let peer_id = add_active_peer::<S, A>(&mut peerdb);
    let address = peerdb.peers.get(&peer_id).unwrap().address.as_bannable();

    peerdb.ban_peer(&peer_id);

    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(peerdb.is_address_banned(&address));

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!peerdb.is_address_banned(&address));
}

#[tokio::test]
async fn unban_peer_mock_tcp() {
    unban_peer::<MockService<TcpTransportSocket>, TestTcpAddressMaker>().await;
}

#[tokio::test]
async fn unban_peer_mock_channels() {
    unban_peer::<MockService<MockChannelTransport>, TestChannelAddressMaker>().await;
}

#[tokio::test]
async fn unban_peer_mock_noise() {
    unban_peer::<MockService<NoiseTcpTransport>, TestTcpAddressMaker>().await;
}
