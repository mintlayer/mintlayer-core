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
    error::{P2pError, PeerError},
    net::{self, libp2p::Libp2pService, ConnectivityService},
    swarm::tests::make_peer_manager,
};
use common::chain::config;
use libp2p::Multiaddr;
use std::sync::Arc;
use test_utils::make_libp2p_addr;

// ban peer whose connected to us
#[tokio::test]
async fn ban_connected_peer() {
    let config = Arc::new(config::create_mainnet());
    let mut swarm1 =
        make_peer_manager::<Libp2pService>(make_libp2p_addr(), Arc::clone(&config)).await;
    let mut swarm2 = make_peer_manager::<Libp2pService>(make_libp2p_addr(), config).await;

    let addr = swarm2.handle.local_addr().await.unwrap().unwrap();
    let (_conn1_res, conn2_res) =
        tokio::join!(swarm1.handle.connect(addr), swarm2.handle.poll_next(),);

    if let Ok(net::types::ConnectivityEvent::IncomingConnection { peer_info, addr }) = conn2_res {
        swarm2.accept_inbound_connection(addr, peer_info).await.unwrap();
    }

    let peer_id = *swarm1.handle_mut().peer_id();
    assert_eq!(swarm2.adjust_peer_score(peer_id, 1000).await, Ok(()));
    assert!(!swarm2.validate_peer_id(&peer_id));
    assert!(std::matches!(
        swarm2.handle_mut().poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionClosed { .. })
    ));
}

#[tokio::test]
async fn banned_peer_attempts_to_connect() {
    let config = Arc::new(config::create_mainnet());
    let mut swarm1 =
        make_peer_manager::<Libp2pService>(make_libp2p_addr(), Arc::clone(&config)).await;
    let mut swarm2 = make_peer_manager::<Libp2pService>(make_libp2p_addr(), config).await;

    let addr = swarm2.handle.local_addr().await.unwrap().unwrap();
    let (_conn1_res, conn2_res) =
        tokio::join!(swarm1.handle.connect(addr), swarm2.handle.poll_next(),);

    if let Ok(net::types::ConnectivityEvent::IncomingConnection { peer_info, addr }) = conn2_res {
        swarm2.accept_inbound_connection(addr, peer_info).await.unwrap();
    }

    let peer_id = *swarm1.handle_mut().peer_id();
    assert_eq!(swarm2.adjust_peer_score(peer_id, 1000).await, Ok(()));
    assert!(!swarm2.validate_peer_id(&peer_id));
    assert!(std::matches!(
        swarm2.handle_mut().poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionClosed { .. })
    ));

    // try to restablish connection, it timeouts because it's rejected in the backend
    let addr = swarm2.handle.local_addr().await.unwrap().unwrap();
    tokio::spawn(async move { swarm1.handle.connect(addr).await });

    tokio::select! {
        _event = swarm2.handle.poll_next() => {
            panic!("did not expect event, received {:?}", _event)
        },
        _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
    }
}

// attempt to connect to banned peer
#[tokio::test]
async fn connect_to_banned_peer() {
    let config = Arc::new(config::create_mainnet());
    let mut swarm1 =
        make_peer_manager::<Libp2pService>(make_libp2p_addr(), Arc::clone(&config)).await;
    let mut swarm2 = make_peer_manager::<Libp2pService>(make_libp2p_addr(), config).await;

    let addr = swarm2.handle.local_addr().await.unwrap().unwrap();
    let (_conn1_res, conn2_res) =
        tokio::join!(swarm1.handle.connect(addr), swarm2.handle.poll_next(),);

    if let Ok(net::types::ConnectivityEvent::IncomingConnection { peer_info, addr }) = conn2_res {
        swarm2.accept_inbound_connection(addr, peer_info).await.unwrap();
    }

    let peer_id = *swarm1.handle_mut().peer_id();
    assert_eq!(swarm2.adjust_peer_score(peer_id, 1000).await, Ok(()));
    assert!(!swarm2.validate_peer_id(&peer_id));
    assert!(std::matches!(
        swarm2.handle_mut().poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionClosed { .. })
    ));

    let remote_addr = swarm1.handle.local_addr().await.unwrap().unwrap();
    let remote_id = *swarm1.handle.peer_id();

    tokio::spawn(async move {
        loop {
            let _ = swarm1.handle.poll_next().await.unwrap();
        }
    });

    swarm2.handle.connect(remote_addr.clone()).await.unwrap();
    if let Ok(net::types::ConnectivityEvent::ConnectionError { addr, error }) =
        swarm2.handle.poll_next().await
    {
        assert_eq!(remote_addr, addr);
        assert_eq!(
            error,
            P2pError::PeerError(PeerError::BannedPeer(remote_id.to_string()))
        );
    }
}

#[tokio::test]
async fn validate_invalid_outbound_connection() {
    let config = Arc::new(config::create_mainnet());
    let mut swarm =
        make_peer_manager::<Libp2pService>(make_libp2p_addr(), Arc::clone(&config)).await;

    // valid connection
    let peer_id = libp2p::PeerId::random();
    let res = swarm
        .accept_connection(net::types::PeerInfo::<Libp2pService> {
            peer_id,
            magic_bytes: *config.magic_bytes(),
            version: common::primitives::semver::SemVer::new(0, 1, 0),
            agent: None,
            protocols: vec![
                "/meshsub/1.1.0".to_string(),
                "/meshsub/1.0.0".to_string(),
                "/ipfs/ping/1.0.0".to_string(),
                "/ipfs/id/1.0.0".to_string(),
                "/ipfs/id/push/1.0.0".to_string(),
                "/mintlayer/sync/0.1.0".to_string(),
            ],
        })
        .await;
    assert_eq!(swarm.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(!swarm.peerdb.is_id_banned(&peer_id));

    // invalid magic bytes
    let peer_id = libp2p::PeerId::random();
    let res = swarm
        .accept_connection(net::types::PeerInfo::<Libp2pService> {
            peer_id,
            magic_bytes: [1, 2, 3, 4],
            version: common::primitives::semver::SemVer::new(0, 1, 0),
            agent: None,
            protocols: vec![
                "/meshsub/1.1.0".to_string(),
                "/meshsub/1.0.0".to_string(),
                "/ipfs/ping/1.0.0".to_string(),
                "/ipfs/id/1.0.0".to_string(),
                "/ipfs/id/push/1.0.0".to_string(),
                "/mintlayer/sync/0.1.0".to_string(),
            ],
        })
        .await;
    assert_eq!(swarm.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(swarm.peerdb.is_id_banned(&peer_id));

    // invalid version
    let peer_id = libp2p::PeerId::random();
    let res = swarm
        .accept_connection(net::types::PeerInfo::<Libp2pService> {
            peer_id,
            magic_bytes: *config.magic_bytes(),
            version: common::primitives::semver::SemVer::new(1, 1, 1),
            agent: None,
            protocols: vec![
                "/meshsub/1.1.0".to_string(),
                "/meshsub/1.0.0".to_string(),
                "/ipfs/ping/1.0.0".to_string(),
                "/ipfs/id/1.0.0".to_string(),
                "/ipfs/id/push/1.0.0".to_string(),
                "/mintlayer/sync/0.1.0".to_string(),
            ],
        })
        .await;
    assert_eq!(swarm.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(swarm.peerdb.is_id_banned(&peer_id));

    // protocol missing
    let peer_id = libp2p::PeerId::random();
    let res = swarm
        .accept_connection(net::types::PeerInfo::<Libp2pService> {
            peer_id,
            magic_bytes: *config.magic_bytes(),
            version: common::primitives::semver::SemVer::new(0, 1, 0),
            agent: None,
            protocols: vec![
                "/meshsub/1.1.0".to_string(),
                "/meshsub/1.0.0".to_string(),
                "/ipfs/ping/1.0.0".to_string(),
                "/ipfs/id/push/1.0.0".to_string(),
                "/mintlayer/sync/0.1.0".to_string(),
            ],
        })
        .await;
    assert_eq!(swarm.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(swarm.peerdb.is_id_banned(&peer_id));
}

#[tokio::test]
async fn validate_invalid_inbound_connection() {
    let config = Arc::new(config::create_mainnet());
    let mut swarm =
        make_peer_manager::<Libp2pService>(make_libp2p_addr(), Arc::clone(&config)).await;

    // valid connection
    let peer_id = libp2p::PeerId::random();
    let res = swarm
        .accept_inbound_connection(
            Multiaddr::empty(),
            net::types::PeerInfo::<Libp2pService> {
                peer_id,
                magic_bytes: *config.magic_bytes(),
                version: common::primitives::semver::SemVer::new(0, 1, 0),
                agent: None,
                protocols: vec![
                    "/meshsub/1.1.0".to_string(),
                    "/meshsub/1.0.0".to_string(),
                    "/ipfs/ping/1.0.0".to_string(),
                    "/ipfs/id/1.0.0".to_string(),
                    "/ipfs/id/push/1.0.0".to_string(),
                    "/mintlayer/sync/0.1.0".to_string(),
                ],
            },
        )
        .await;
    assert_eq!(swarm.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(!swarm.peerdb.is_id_banned(&peer_id));

    // invalid magic bytes
    let peer_id = libp2p::PeerId::random();
    let res = swarm
        .accept_inbound_connection(
            Multiaddr::empty(),
            net::types::PeerInfo::<Libp2pService> {
                peer_id,
                magic_bytes: [1, 2, 3, 4],
                version: common::primitives::semver::SemVer::new(0, 1, 0),
                agent: None,
                protocols: vec![
                    "/meshsub/1.1.0".to_string(),
                    "/meshsub/1.0.0".to_string(),
                    "/ipfs/ping/1.0.0".to_string(),
                    "/ipfs/id/1.0.0".to_string(),
                    "/ipfs/id/push/1.0.0".to_string(),
                    "/mintlayer/sync/0.1.0".to_string(),
                ],
            },
        )
        .await;
    assert_eq!(swarm.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(swarm.peerdb.is_id_banned(&peer_id));

    // invalid version
    let peer_id = libp2p::PeerId::random();
    let res = swarm
        .accept_inbound_connection(
            Multiaddr::empty(),
            net::types::PeerInfo::<Libp2pService> {
                peer_id,
                magic_bytes: *config.magic_bytes(),
                version: common::primitives::semver::SemVer::new(1, 1, 1),
                agent: None,
                protocols: vec![
                    "/meshsub/1.1.0".to_string(),
                    "/meshsub/1.0.0".to_string(),
                    "/ipfs/ping/1.0.0".to_string(),
                    "/ipfs/id/1.0.0".to_string(),
                    "/ipfs/id/push/1.0.0".to_string(),
                    "/mintlayer/sync/0.1.0".to_string(),
                ],
            },
        )
        .await;
    assert_eq!(swarm.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(swarm.peerdb.is_id_banned(&peer_id));

    // protocol missing
    let peer_id = libp2p::PeerId::random();
    let res = swarm
        .accept_inbound_connection(
            Multiaddr::empty(),
            net::types::PeerInfo::<Libp2pService> {
                peer_id,
                magic_bytes: *config.magic_bytes(),
                version: common::primitives::semver::SemVer::new(0, 1, 0),
                agent: None,
                protocols: vec![
                    "/meshsub/1.1.0".to_string(),
                    "/meshsub/1.0.0".to_string(),
                    "/ipfs/ping/1.0.0".to_string(),
                    "/ipfs/id/push/1.0.0".to_string(),
                    "/mintlayer/sync/0.1.0".to_string(),
                ],
            },
        )
        .await;
    assert_eq!(swarm.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(swarm.peerdb.is_id_banned(&peer_id));
}
