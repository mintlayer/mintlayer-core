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
use super::*;
use crypto::random::{Rng, SliceRandom};

// response contains more than 2000 headers
#[tokio::test]
async fn too_many_headers() {
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let (mut mgr, _conn, _sync, _pubsub, _swarm) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let peer_id = PeerId::random();
    mgr.register_peer(peer_id).await.unwrap();

    let headers = test_utils::create_n_blocks(Arc::clone(&config), config.genesis_block(), 2001)
        .iter()
        .map(|block| block.header().clone())
        .collect::<Vec<_>>();

    assert_eq!(
        mgr.validate_header_response(&peer_id, headers,).await,
        Err(P2pError::ProtocolError(ProtocolError::InvalidMessage)),
    );
}

// header response is empty
#[tokio::test]
async fn empty_response() {
    let (mut mgr, _conn, _sync, _pubsub, _swarm) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let peer_id = PeerId::random();
    mgr.register_peer(peer_id).await.unwrap();

    assert_eq!(
        mgr.validate_header_response(&peer_id, vec![]).await,
        Ok(None),
    );
}

// valid response with headers in order and the first header attaching to local chain
#[tokio::test]
async fn valid_response() {
    let mut rng = crypto::random::make_pseudo_rng();
    let config = Arc::new(common::chain::config::create_unit_test_config());

    let (mut mgr, _conn, _sync, _pubsub, _swarm) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let peer_id = PeerId::random();
    mgr.register_peer(peer_id).await.unwrap();

    let headers = test_utils::create_n_blocks(
        Arc::clone(&config),
        config.genesis_block(),
        rng.gen_range(1..100),
    )
    .iter()
    .map(|block| block.header().clone())
    .collect::<Vec<_>>();
    let first = headers[0].clone();

    assert_eq!(
        mgr.validate_header_response(&peer_id, headers,).await,
        Ok(Some(first)),
    );
}

// previous block is `None`
#[tokio::test]
async fn prev_block_is_none() {
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let (mut mgr, _conn, _sync, _pubsub, _swarm) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let peer_id = PeerId::random();
    mgr.register_peer(peer_id).await.unwrap();

    assert_eq!(
        mgr.validate_header_response(&peer_id, vec![config.genesis_block().header().clone()],)
            .await,
        Err(P2pError::ProtocolError(ProtocolError::InvalidMessage)),
    );
}

// the first header doesn't attach to local chain
#[tokio::test]
async fn header_doesnt_attach_to_local_chain() {
    let mut rng = crypto::random::make_pseudo_rng();
    let config = Arc::new(common::chain::config::create_unit_test_config());

    let (mut mgr, _conn, _sync, _pubsub, _swarm) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let peer_id = PeerId::random();
    mgr.register_peer(peer_id).await.unwrap();

    let headers = test_utils::create_n_blocks(
        Arc::clone(&config),
        config.genesis_block(),
        rng.gen_range(2..100),
    )
    .iter()
    .map(|block| block.header().clone())
    .collect::<Vec<_>>();

    assert_eq!(
        mgr.validate_header_response(&peer_id, headers[1..].to_vec(),).await,
        Err(P2pError::ProtocolError(ProtocolError::InvalidMessage)),
    );
}

// valid headers but they are not in order
#[tokio::test]
async fn headers_not_in_order() {
    let mut rng = crypto::random::make_pseudo_rng();
    let config = Arc::new(common::chain::config::create_unit_test_config());

    let (mut mgr, _conn, _sync, _pubsub, _swarm) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let peer_id = PeerId::random();
    mgr.register_peer(peer_id).await.unwrap();

    let mut headers = test_utils::create_n_blocks(
        Arc::clone(&config),
        config.genesis_block(),
        rng.gen_range(5..100),
    )
    .iter()
    .map(|block| block.header().clone())
    .collect::<Vec<_>>();
    headers.shuffle(&mut rng);

    assert_eq!(
        mgr.validate_header_response(&peer_id, headers[1..].to_vec(),).await,
        Err(P2pError::ProtocolError(ProtocolError::InvalidMessage)),
    );
}

// peer state is incorrect to be sending header responses
#[tokio::test]
async fn invalid_state() {
    let mut rng = crypto::random::make_pseudo_rng();
    let config = Arc::new(common::chain::config::create_unit_test_config());

    let (mut mgr, _conn, _sync, _pubsub, _swarm) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let peer_id = PeerId::random();
    mgr.register_peer(peer_id).await.unwrap();

    mgr.peers.get_mut(&peer_id).unwrap().set_state(peer::PeerSyncState::Unknown);

    let headers = test_utils::create_n_blocks(
        Arc::clone(&config),
        config.genesis_block(),
        rng.gen_range(1..100),
    )
    .iter()
    .map(|block| block.header().clone())
    .collect::<Vec<_>>();

    assert_eq!(
        mgr.validate_header_response(&peer_id, headers,).await,
        Err(P2pError::ProtocolError(ProtocolError::InvalidMessage)),
    );
}

// peer doesn't exist
#[tokio::test]
async fn peer_doesnt_exist() {
    let (mut mgr, _conn, _sync, _pubsub, _swarm) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;

    assert_eq!(
        mgr.validate_header_response(&PeerId::random(), vec![]).await,
        Err(P2pError::PeerError(PeerError::PeerDoesntExist)),
    );
}
