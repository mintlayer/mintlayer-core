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
        types::{PeerInfo, PubSubTopic},
        AsBannableAddress,
    },
    peer_manager::peerdb::PeerDb,
    testing_utils::{RandomAddressMaker, TestChannelAddressMaker, TestTcpAddressMaker},
    NetworkingService,
};

fn make_peer_info<S>() -> (S::PeerId, PeerInfo<S>)
where
    S: NetworkingService<PeerId = MockPeerId>,
{
    let peer_id = MockPeerId::new();

    (
        peer_id,
        PeerInfo::<S> {
            peer_id,
            magic_bytes: [1, 2, 3, 4],
            version: common::primitives::semver::SemVer::new(0, 1, 0),
            agent: None,
            subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions].into_iter().collect(),
        },
    )
}

fn add_banned_peer_address<S>(peerdb: &mut PeerDb<S>, address: S::Address) -> S::PeerId
where
    S: NetworkingService<PeerId = MockPeerId>,
{
    let (id, info) = make_peer_info::<S>();
    peerdb.register_peer_info(address, info);
    peerdb.ban_peer(&id);

    id
}

fn add_banned_peer<S, A>(peerdb: &mut PeerDb<S>) -> S::PeerId
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    add_banned_peer_address::<S>(peerdb, A::new())
}

async fn unban_peer<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig {
        bind_address: Default::default(),
        ban_threshold: Default::default(),
        ban_duration: Duration::from_secs(2).into(),
        outbound_connection_timeout: Default::default(),
        mdns_config: Default::default(),
        node_type: Default::default(),
    }));

    let id = add_banned_peer::<S, A>(&mut peerdb);
    let address = peerdb.peers().get(&id).unwrap().address().unwrap().as_bannable();

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
