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
use crate::{
    error::{P2pError, PeerError, ProtocolError},
    net::libp2p::{
        types::ConnectivityEvent,
        types::{self, PendingState},
        DialError,
    },
};
use libp2p::{
    core::connection::{ConnectedPoint, Endpoint},
    swarm::DialError as Libp2pDialError,
    Multiaddr, PeerId,
};

#[tokio::test]
async fn connection_established_dialer_valid() {
    let (mut backend, _cmd_tx, _conn_rx, _pubsub_rx, _sync_rx) = make_libp2p(
        common::chain::config::create_mainnet(),
        test_utils::make_address("/ip6/::1/tcp/"),
        &[],
        false,
    )
    .await;
    let peer_id = PeerId::random();
    backend
        .swarm
        .behaviour_mut()
        .pending_conns
        .insert(peer_id, PendingState::Dialed(Multiaddr::empty()));

    assert_eq!(
        backend
            .on_connection_established(
                peer_id,
                ConnectedPoint::Dialer {
                    address: Multiaddr::empty(),
                    role_override: Endpoint::Dialer,
                }
            )
            .await,
        Ok(())
    );
    assert!(std::matches!(
        backend.swarm.behaviour_mut().pending_conns.remove(&peer_id),
        Some(types::PendingState::OutboundAccepted(_))
    ));
}

#[tokio::test]
async fn connection_established_dialer_invalid_state() {
    let (mut backend, _cmd_tx, _conn_rx, _pubsub_rx, _sync_rx) = make_libp2p(
        common::chain::config::create_mainnet(),
        test_utils::make_address("/ip6/::1/tcp/"),
        &[],
        false,
    )
    .await;
    let peer_id = PeerId::random();
    backend
        .swarm
        .behaviour_mut()
        .pending_conns
        .insert(peer_id, PendingState::OutboundAccepted(Multiaddr::empty()));

    assert_eq!(
        backend
            .on_connection_established(
                peer_id,
                ConnectedPoint::Dialer {
                    address: Multiaddr::empty(),
                    role_override: Endpoint::Dialer,
                }
            )
            .await,
        Err(P2pError::ProtocolError(ProtocolError::InvalidState(
            "OutboundAccepted",
            "Dialed"
        )))
    );

    backend
        .swarm
        .behaviour_mut()
        .pending_conns
        .insert(peer_id, PendingState::InboundAccepted(Multiaddr::empty()));
    assert_eq!(
        backend
            .on_connection_established(
                peer_id,
                ConnectedPoint::Dialer {
                    address: Multiaddr::empty(),
                    role_override: Endpoint::Dialer,
                }
            )
            .await,
        Err(P2pError::ProtocolError(ProtocolError::InvalidState(
            "InboundAccepted",
            "Dialed"
        )))
    );
}

#[tokio::test]
async fn connection_established_dialer_peer_doesnt_exist() {
    let (mut backend, _cmd_tx, _conn_rx, _pubsub_rx, _sync_rx) = make_libp2p(
        common::chain::config::create_mainnet(),
        test_utils::make_address("/ip6/::1/tcp/"),
        &[],
        false,
    )
    .await;

    assert_eq!(
        backend
            .on_connection_established(
                PeerId::random(),
                ConnectedPoint::Dialer {
                    address: Multiaddr::empty(),
                    role_override: Endpoint::Dialer,
                }
            )
            .await,
        Err(P2pError::PeerError(PeerError::PeerDoesntExist))
    );
}

#[tokio::test]
async fn connection_established_listener_valid() {
    let (mut backend, _cmd_tx, _conn_rx, _pubsub_rx, _sync_rx) = make_libp2p(
        common::chain::config::create_mainnet(),
        test_utils::make_address("/ip6/::1/tcp/"),
        &[],
        false,
    )
    .await;
    let peer_id = PeerId::random();

    assert_eq!(
        backend
            .on_connection_established(
                peer_id,
                ConnectedPoint::Listener {
                    local_addr: Multiaddr::empty(),
                    send_back_addr: Multiaddr::empty(),
                }
            )
            .await,
        Ok(()),
    );

    assert!(std::matches!(
        backend.swarm.behaviour_mut().pending_conns.remove(&peer_id),
        Some(types::PendingState::InboundAccepted { .. })
    ));
}

#[tokio::test]
async fn connection_established_listener_already_exists() {
    let (mut backend, _cmd_tx, _conn_rx, _pubsub_rx, _sync_rx) = make_libp2p(
        common::chain::config::create_mainnet(),
        test_utils::make_address("/ip6/::1/tcp/"),
        &[],
        false,
    )
    .await;

    let peer_id = PeerId::random();
    backend.swarm.behaviour_mut().pending_conns.insert(
        peer_id,
        types::PendingState::InboundAccepted(Multiaddr::empty()),
    );

    assert_eq!(
        backend
            .on_connection_established(
                peer_id,
                ConnectedPoint::Listener {
                    local_addr: Multiaddr::empty(),
                    send_back_addr: Multiaddr::empty(),
                }
            )
            .await,
        Err(P2pError::ProtocolError(ProtocolError::InvalidState("", "")))
    );
}

#[tokio::test]
async fn outgoing_error_peer_id_none() {
    let (mut backend, _cmd_tx, _conn_rx, _pubsub_rx, _sync_rx) = make_libp2p(
        common::chain::config::create_mainnet(),
        test_utils::make_address("/ip6/::1/tcp/"),
        &[],
        false,
    )
    .await;

    assert_eq!(
        backend.on_outgoing_connection_error(None, Libp2pDialError::LocalPeerId).await,
        Ok(())
    );
}

#[tokio::test]
async fn outgoing_error_dialed_exists() {
    let (mut backend, _cmd_tx, mut _conn_rx, _pubsub_rx, _sync_rx) = make_libp2p(
        common::chain::config::create_mainnet(),
        test_utils::make_address("/ip6/::1/tcp/"),
        &[],
        false,
    )
    .await;
    let peer_id = PeerId::random();
    backend
        .swarm
        .behaviour_mut()
        .pending_conns
        .insert(peer_id, types::PendingState::Dialed(Multiaddr::empty()));

    assert_eq!(
        backend
            .on_outgoing_connection_error(Some(peer_id), Libp2pDialError::Banned,)
            .await,
        Ok(())
    );

    match _conn_rx.try_recv() {
        Ok(ConnectivityEvent::ConnectionError {
            addr: _,
            error: P2pError::DialError(DialError::IoError(std::io::ErrorKind::ConnectionRefused)),
        }) => {}
        _ => panic!("invalid event received, expected `ConnectionRefused`"),
    }
}

#[tokio::test]
async fn outgoing_error_outbound_exists() {
    let (mut backend, _cmd_tx, _conn_rx, _pubsub_rx, _sync_rx) = make_libp2p(
        common::chain::config::create_mainnet(),
        test_utils::make_address("/ip6/::1/tcp/"),
        &[],
        false,
    )
    .await;
    let peer_id = PeerId::random();
    backend.swarm.behaviour_mut().pending_conns.insert(
        peer_id,
        types::PendingState::OutboundAccepted(Multiaddr::empty()),
    );

    assert_eq!(
        backend
            .on_outgoing_connection_error(Some(peer_id), Libp2pDialError::Aborted)
            .await,
        Ok(())
    );
}

#[tokio::test]
async fn outgoing_error_peer_doesnt_exist() {
    let (mut backend, _cmd_tx, _conn_rx, _pubsub_rx, _sync_rx) = make_libp2p(
        common::chain::config::create_mainnet(),
        test_utils::make_address("/ip6/::1/tcp/"),
        &[],
        false,
    )
    .await;
    assert_eq!(
        backend
            .on_outgoing_connection_error(Some(PeerId::random()), Libp2pDialError::NoAddresses)
            .await,
        Err(P2pError::DialError(DialError::NoAddresses))
    );
}
