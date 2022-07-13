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

use crate::{
    error::{DialError, P2pError, ProtocolError},
    net::{self, libp2p::Libp2pService, mock::MockService, ConnectivityService},
    swarm::{self, tests::make_peer_manager},
};
use common::chain::config;
use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
use logging::log;
use std::{net::SocketAddr, sync::Arc};
use test_utils::make_libp2p_addr;

// try to connect to an address that no one listening on and verify it fails
#[tokio::test]
async fn test_swarm_connect_mock() {
    let addr: SocketAddr = "[::1]:0".parse().unwrap();
    let config = Arc::new(config::create_mainnet());
    let mut swarm = make_peer_manager::<MockService>(addr, config).await;

    let addr: SocketAddr = "[::1]:1".parse().unwrap();
    // TODO:
    let _ = swarm.connect(addr).await;
}

// try to connect to an address that no one listening on and verify it fails
#[tokio::test]
async fn test_swarm_connect_libp2p() {
    let config = Arc::new(config::create_mainnet());
    let mut swarm = make_peer_manager::<Libp2pService>(make_libp2p_addr(), config).await;

    let addr: Multiaddr =
        "/ip6/::1/tcp/6666/p2p/12D3KooWRn14SemPVxwzdQNg8e8Trythiww1FWrNfPbukYBmZEbJ"
            .parse()
            .unwrap();
    swarm.connect(addr).await.unwrap();
    assert!(std::matches!(
        swarm.handle.poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionError {
            addr: _,
            error: P2pError::DialError(DialError::IoError(std::io::ErrorKind::ConnectionRefused))
        })
    ));
}

// verify that the auto-connect functionality works if the number of active connections
// is below the desired threshold and there are idle peers in the peerdb
#[tokio::test]
async fn test_auto_connect_libp2p() {
    let config = Arc::new(config::create_mainnet());
    let mut swarm = make_peer_manager::<Libp2pService>(make_libp2p_addr(), config.clone()).await;
    let mut swarm2 = make_peer_manager::<Libp2pService>(make_libp2p_addr(), config).await;

    let addr = swarm2.handle.local_addr().await.unwrap().unwrap();
    let id: PeerId = if let Some(Protocol::P2p(peer)) = addr.iter().last() {
        PeerId::from_multihash(peer).unwrap()
    } else {
        panic!("invalid multiaddr");
    };

    tokio::spawn(async move {
        log::debug!("staring libp2p service");
        loop {
            assert!(swarm2.handle.poll_next().await.is_ok());
        }
    });

    // "discover" the other libp2p service
    swarm.peer_discovered(&[net::types::AddrInfo {
        id,
        ip4: vec![],
        ip6: vec![addr],
    }]);
    swarm.heartbeat().await.unwrap();
    assert_eq!(swarm.pending.len(), 1);
    assert!(std::matches!(
        swarm.handle.poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionAccepted { .. })
    ));
}

#[tokio::test]
async fn connect_outbound_same_network() {
    let config = Arc::new(config::create_mainnet());
    let mut swarm1 = make_peer_manager::<Libp2pService>(make_libp2p_addr(), config.clone()).await;

    let mut swarm2 = make_peer_manager::<Libp2pService>(make_libp2p_addr(), config).await;
    let addr = swarm2.handle.local_addr().await.unwrap().unwrap();

    let (_conn1_res, _conn2_res) =
        tokio::join!(swarm1.handle.connect(addr), swarm2.handle.poll_next());

    assert!(std::matches!(
        swarm1.handle.poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionAccepted { .. })
    ));
}

#[tokio::test]
async fn test_validate_supported_protocols() {
    let config = Arc::new(config::create_mainnet());
    let swarm = make_peer_manager::<Libp2pService>(make_libp2p_addr(), config).await;

    // all needed protocols
    assert!(swarm.validate_supported_protocols(&[
        "/meshsub/1.1.0".to_string(),
        "/meshsub/1.0.0".to_string(),
        "/ipfs/ping/1.0.0".to_string(),
        "/ipfs/id/1.0.0".to_string(),
        "/ipfs/id/push/1.0.0".to_string(),
        "/mintlayer/sync/0.1.0".to_string(),
    ]));

    // all needed protocols + 2 extra
    assert!(swarm.validate_supported_protocols(&[
        "/meshsub/1.1.0".to_string(),
        "/meshsub/1.0.0".to_string(),
        "/ipfs/ping/1.0.0".to_string(),
        "/ipfs/id/1.0.0".to_string(),
        "/ipfs/id/push/1.0.0".to_string(),
        "/mintlayer/sync/0.1.0".to_string(),
        "/mintlayer/extra/0.1.0".to_string(),
        "/mintlayer/extra-test/0.2.0".to_string(),
    ]));

    // all needed protocols but wrong version for sync
    assert!(!swarm.validate_supported_protocols(&[
        "/meshsub/1.1.0".to_string(),
        "/meshsub/1.0.0".to_string(),
        "/ipfs/ping/1.0.0".to_string(),
        "/ipfs/id/1.0.0".to_string(),
        "/ipfs/id/push/1.0.0".to_string(),
        "/mintlayer/sync/0.2.0".to_string(),
    ]));

    // ping protocol missing
    assert!(!swarm.validate_supported_protocols(&[
        "/meshsub/1.1.0".to_string(),
        "/meshsub/1.0.0".to_string(),
        "/ipfs/id/1.0.0".to_string(),
        "/ipfs/id/push/1.0.0".to_string(),
        "/mintlayer/sync/0.1.0".to_string(),
    ]));
}

#[tokio::test]
async fn connect_outbound_different_network() {
    let config = Arc::new(config::create_mainnet());
    let mut swarm1 =
        make_peer_manager::<Libp2pService>(make_libp2p_addr(), Arc::clone(&config)).await;
    let mut swarm2 = make_peer_manager::<Libp2pService>(
        make_libp2p_addr(),
        Arc::new(common::chain::config::Builder::test_chain().magic_bytes([1, 2, 3, 4]).build()),
    )
    .await;

    let addr = swarm2.handle.local_addr().await.unwrap().unwrap();
    tokio::spawn(async move { swarm2.handle.poll_next().await.unwrap() });
    swarm1.handle.connect(addr).await.unwrap();

    if let Ok(net::types::ConnectivityEvent::ConnectionAccepted { peer_info, addr: _ }) =
        swarm1.handle.poll_next().await
    {
        assert_ne!(peer_info.magic_bytes, *config.magic_bytes());
    }
}

#[tokio::test]
async fn connect_inbound_same_network() {
    let config = Arc::new(config::create_mainnet());
    let mut swarm1 = make_peer_manager::<Libp2pService>(make_libp2p_addr(), config.clone()).await;
    let mut swarm2 = make_peer_manager::<Libp2pService>(make_libp2p_addr(), config).await;

    let (_conn1_res, conn2_res) = tokio::join!(
        swarm1.handle.connect(swarm2.handle.local_addr().await.unwrap().unwrap()),
        swarm2.handle.poll_next()
    );
    let conn2_res: net::types::ConnectivityEvent<Libp2pService> = conn2_res.unwrap();
    if let net::types::ConnectivityEvent::IncomingConnection { peer_info, addr } = conn2_res {
        assert_eq!(
            swarm2.accept_inbound_connection(addr, peer_info).await,
            Ok(())
        );
    } else {
        panic!("invalid event received");
    }
}

#[tokio::test]
async fn connect_inbound_different_network() {
    let mut swarm1 =
        make_peer_manager::<Libp2pService>(make_libp2p_addr(), Arc::new(config::create_mainnet()))
            .await;
    let mut swarm2 = make_peer_manager::<Libp2pService>(
        make_libp2p_addr(),
        Arc::new(common::chain::config::Builder::test_chain().magic_bytes([1, 2, 3, 4]).build()),
    )
    .await;

    let (_conn1_res, conn2_res) = tokio::join!(
        swarm1.handle.connect(swarm2.handle.local_addr().await.unwrap().unwrap()),
        swarm2.handle.poll_next()
    );
    let conn2_res: net::types::ConnectivityEvent<Libp2pService> = conn2_res.unwrap();

    if let net::types::ConnectivityEvent::IncomingConnection { peer_info, addr } = conn2_res {
        assert_eq!(
            swarm2.accept_inbound_connection(addr, peer_info).await,
            Err(P2pError::ProtocolError(ProtocolError::DifferentNetwork(
                [1, 2, 3, 4],
                *config::create_mainnet().magic_bytes(),
            )))
        );
    } else {
        panic!("invalid event received");
    }
}

#[tokio::test]
async fn remote_closes_connection() {
    let mut swarm1 =
        make_peer_manager::<Libp2pService>(make_libp2p_addr(), Arc::new(config::create_mainnet()))
            .await;
    let mut swarm2 =
        make_peer_manager::<Libp2pService>(make_libp2p_addr(), Arc::new(config::create_mainnet()))
            .await;

    let (_conn1_res, conn2_res) = tokio::join!(
        swarm1.handle.connect(swarm2.handle.local_addr().await.unwrap().unwrap()),
        swarm2.handle.poll_next()
    );
    let conn2_res: net::types::ConnectivityEvent<Libp2pService> = conn2_res.unwrap();

    assert!(std::matches!(
        conn2_res,
        net::types::ConnectivityEvent::IncomingConnection { .. }
    ));
    assert!(std::matches!(
        swarm1.handle.poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionAccepted { .. })
    ));

    assert_eq!(
        swarm2.handle.disconnect(*swarm1.handle.peer_id()).await,
        Ok(())
    );
    assert!(std::matches!(
        swarm1.handle.poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionClosed { .. })
    ));
}

#[tokio::test]
async fn inbound_connection_too_many_peers() {
    let config = Arc::new(config::create_mainnet());
    let mut swarm1 =
        make_peer_manager::<Libp2pService>(make_libp2p_addr(), Arc::clone(&config)).await;

    let mut swarm2 =
        make_peer_manager::<Libp2pService>(make_libp2p_addr(), Arc::clone(&config)).await;

    // add `MAX_ACTIVE_CONNECTIONS` peers so the next peer that joins is rejected
    for _ in 0..swarm::MAX_ACTIVE_CONNECTIONS {
        let peer_id = PeerId::random();
        let info = swarm::peerdb::PeerContext {
            _info: net::types::PeerInfo {
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
            score: 0,
        };

        swarm1.peers.insert(peer_id, info);
    }
    assert_eq!(swarm1.peers.len(), swarm::MAX_ACTIVE_CONNECTIONS);

    let addr = swarm2.handle.local_addr().await.unwrap().unwrap();
    let (_conn1_res, conn2_res) =
        tokio::join!(swarm1.handle.connect(addr), swarm2.handle.poll_next());
    let _conn2_res: net::types::ConnectivityEvent<Libp2pService> = conn2_res.unwrap();
    let swarm1_id = *swarm1.handle.peer_id();

    // run the first peer manager in the background and poll events from the peer manager
    // that tries to connect to the first manager
    tokio::spawn(async move { swarm1.run().await });

    if let Ok(net::types::ConnectivityEvent::ConnectionClosed { peer_id }) =
        swarm2.handle.poll_next().await
    {
        assert_eq!(peer_id, swarm1_id);
    } else {
        panic!("invalid event received");
    }
}
