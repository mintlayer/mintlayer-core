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
use super::*;
use crate::{
    error::{P2pError, PeerError, ProtocolError},
    net::libp2p::{
        connectivity::*,
        types::{ConnectivityEvent, IdentifyInfoWrapper},
        DialError,
    },
};
use libp2p::{
    core::connection::{ConnectedPoint, Endpoint},
    identify, identity,
    swarm::DialError as Libp2pDialError,
    Multiaddr, PeerId,
};

fn make_empty_info() -> identify::IdentifyInfo {
    identify::IdentifyInfo {
        public_key: identity::Keypair::generate_ed25519().public(),
        protocol_version: "".to_string(),
        agent_version: "".to_string(),
        listen_addrs: vec![],
        protocols: vec![],
        observed_addr: Multiaddr::empty(),
    }
}

#[tokio::test]
async fn connection_established_dialer() {
    let mut connmgr = ConnectionManager::new();

    // unknown peer
    assert_eq!(
        connmgr.handle_dialer_connection_established(&PeerId::random()),
        Err(P2pError::PeerError(PeerError::PeerDoesntExist))
    );

    // known peer in `InboundAccepted` state
    let peer_id = PeerId::random();
    connmgr.connections.insert(
        peer_id,
        types::Connection::new(
            Multiaddr::empty(),
            types::ConnectionState::InboundAccepted,
            None,
        ),
    );
    assert_eq!(
        connmgr.handle_dialer_connection_established(&peer_id),
        Ok(()),
    );
    assert_eq!(
        connmgr.events.front(),
        Some(&types::ConnectionManagerEvent::Control(
            types::ControlEvent::CloseConnection { peer_id },
        )),
    );
    connmgr.events.clear();

    // known peer in `OutboundAccepted` state
    let peer_id = PeerId::random();
    connmgr.connections.insert(
        peer_id,
        types::Connection::new(
            Multiaddr::empty(),
            types::ConnectionState::OutboundAccepted,
            None,
        ),
    );
    assert_eq!(
        connmgr.handle_dialer_connection_established(&peer_id),
        Ok(()),
    );
    assert_eq!(
        connmgr.events.front(),
        Some(&types::ConnectionManagerEvent::Control(
            types::ControlEvent::CloseConnection { peer_id },
        )),
    );
    // assert_eq!(
    //     connmgr.events.front(),
    //     Some(&types::ConnectionManagerEvent::Behaviour(
    //         types::BehaviourEvent::ConnectionClosed { peer_id },
    //     ))
    // );
    connmgr.events.clear();

    // known peer in `Active` state
    let peer_id = PeerId::random();
    connmgr.connections.insert(
        peer_id,
        types::Connection::new(Multiaddr::empty(), types::ConnectionState::Active, None),
    );
    assert_eq!(
        connmgr.handle_dialer_connection_established(&peer_id),
        Ok(()),
    );
    assert_eq!(
        connmgr.events.front(),
        Some(&types::ConnectionManagerEvent::Control(
            types::ControlEvent::CloseConnection { peer_id },
        )),
    );

    // known peer in valid state
    let peer_id = PeerId::random();
    let state1 = types::Connection::new(Multiaddr::empty(), types::ConnectionState::Dialing, None);
    let state2 = types::Connection::new(
        Multiaddr::empty(),
        types::ConnectionState::OutboundAccepted,
        None,
    );

    connmgr.dialing(peer_id, Multiaddr::empty());
    assert!(std::matches!(connmgr.connections.get(&peer_id), conn));
    assert_eq!(
        connmgr.handle_dialer_connection_established(&peer_id),
        Ok(())
    );
    assert!(std::matches!(connmgr.connections.get(&peer_id), state2));
}

#[tokio::test]
async fn connection_established_listener() {
    let mut connmgr = ConnectionManager::new();

    // unknown peer, accept connection
    let peer_id = PeerId::random();
    let conn = types::Connection::new(
        Multiaddr::empty(),
        types::ConnectionState::InboundAccepted,
        None,
    );

    assert_eq!(
        connmgr.handle_listener_connection_established(&peer_id, Multiaddr::empty()),
        Ok(())
    );
    assert!(std::matches!(connmgr.connections.get(&peer_id), conn));

    // known connection. closed
    let peer_id = PeerId::random();

    connmgr.connections.insert(
        peer_id,
        types::Connection::new(Multiaddr::empty(), types::ConnectionState::Active, None),
    );
    assert_eq!(
        connmgr.handle_listener_connection_established(&peer_id, Multiaddr::empty()),
        Ok(())
    );
    assert!(std::matches!(
        connmgr.connections.get(&peer_id).unwrap().state(),
        types::ConnectionState::Closing
    ));
    assert_eq!(
        connmgr.events.front(),
        Some(&types::ConnectionManagerEvent::Control(
            types::ControlEvent::CloseConnection { peer_id },
        )),
    );
}

#[tokio::test]
async fn register_identify_info() {
    let mut connmgr = ConnectionManager::new();

    // unknown peer
    assert_eq!(
        connmgr.register_identify_info(&PeerId::random(), make_empty_info()),
        Err(P2pError::PeerError(PeerError::PeerDoesntExist))
    );

    // peer is dialing
    let peer_id = PeerId::random();

    connmgr.connections.insert(
        peer_id,
        types::Connection::new(Multiaddr::empty(), types::ConnectionState::Dialing, None),
    );
    assert_eq!(
        connmgr.register_identify_info(&peer_id, make_empty_info()),
        Ok(()),
    );
    assert_eq!(
        connmgr.events.front(),
        Some(&types::ConnectionManagerEvent::Control(
            types::ControlEvent::CloseConnection { peer_id },
        )),
    );
    connmgr.events.clear();

    // peer is in state `InboundAccepted`
    let peer_id = PeerId::random();
    let info = make_empty_info();

    connmgr.connections.insert(
        peer_id,
        types::Connection::new(
            Multiaddr::empty(),
            types::ConnectionState::InboundAccepted,
            None,
        ),
    );
    assert_eq!(
        connmgr.register_identify_info(&peer_id, info.clone()),
        Ok(()),
    );
    assert_eq!(
        connmgr.events.front(),
        Some(&types::ConnectionManagerEvent::Behaviour(
            types::BehaviourEvent::InboundAccepted {
                address: Multiaddr::empty(),
                peer_info: IdentifyInfoWrapper::new(info),
            },
        )),
    );
    connmgr.events.clear();

    // peer is in state `OutboundAccepted`
    let peer_id = PeerId::random();
    let info = make_empty_info();

    connmgr.connections.insert(
        peer_id,
        types::Connection::new(
            Multiaddr::empty(),
            types::ConnectionState::OutboundAccepted,
            None,
        ),
    );
    assert_eq!(
        connmgr.register_identify_info(&peer_id, info.clone()),
        Ok(()),
    );
    assert_eq!(
        connmgr.events.front(),
        Some(&types::ConnectionManagerEvent::Behaviour(
            types::BehaviourEvent::OutboundAccepted {
                address: Multiaddr::empty(),
                peer_info: IdentifyInfoWrapper::new(info),
            },
        )),
    );
}

#[tokio::test]
async fn dialing() {
    let mut connmgr = ConnectionManager::new();

    // peer is already in some other state so its state is not changed
    let peer_id = PeerId::random();
    let conn = types::Connection::new(Multiaddr::empty(), types::ConnectionState::Active, None);

    connmgr.connections.insert(peer_id, conn);
    connmgr.dialing(peer_id, Multiaddr::empty());
    assert!(std::matches!(connmgr.connections.get(&peer_id), conn));

    // unknown peer, set of connections is updated
    let peer_id = PeerId::random();
    let conn = types::Connection::new(Multiaddr::empty(), types::ConnectionState::Dialing, None);

    assert!(std::matches!(connmgr.connections.get(&peer_id), None));
    connmgr.dialing(peer_id, Multiaddr::empty());
    assert!(std::matches!(connmgr.connections.get(&peer_id), conn));
}

#[tokio::test]
async fn handle_dial_failure() {
    let mut connmgr = ConnectionManager::new();

    // unknown peer
    assert_eq!(
        connmgr.handle_dialer_connection_established(&PeerId::random()),
        Err(P2pError::PeerError(PeerError::PeerDoesntExist))
    );

    // pending connections emit `ConnectionRefused` error
    assert!(
        types::Connection::new(Multiaddr::empty(), types::ConnectionState::Dialing, None)
            .is_pending()
    );
    assert!(types::Connection::new(
        Multiaddr::empty(),
        types::ConnectionState::InboundAccepted,
        None
    )
    .is_pending());
    assert!(types::Connection::new(
        Multiaddr::empty(),
        types::ConnectionState::OutboundAccepted,
        None
    )
    .is_pending());

    let peer_id = PeerId::random();
    let info = make_empty_info();
    let addr = Multiaddr::empty();

    connmgr.connections.insert(
        peer_id,
        types::Connection::new(addr, types::ConnectionState::InboundAccepted, None),
    );
    assert_eq!(connmgr.handle_dial_failure(&peer_id), Ok(()));
    assert_eq!(connmgr.events.front(), None);
    connmgr.events.clear();

    // other connections emit control event to close the connection
    let peer_id = PeerId::random();

    connmgr.connections.insert(
        peer_id,
        types::Connection::new(Multiaddr::empty(), types::ConnectionState::Active, None),
    );
    assert_eq!(connmgr.handle_dial_failure(&peer_id), Ok(()));
    assert_eq!(
        connmgr.events.front(),
        Some(&types::ConnectionManagerEvent::Control(
            types::ControlEvent::CloseConnection { peer_id },
        )),
    );
}

#[tokio::test]
async fn handle_connection_refused() {
    let mut connmgr = ConnectionManager::new();

    // unknown peer
    assert_eq!(
        connmgr.handle_dialer_connection_established(&PeerId::random()),
        Err(P2pError::PeerError(PeerError::PeerDoesntExist))
    );

    // known connection
    let peer_id = PeerId::random();

    connmgr.connections.insert(
        peer_id,
        types::Connection::new(Multiaddr::empty(), types::ConnectionState::Dialing, None),
    );
    assert_eq!(connmgr.handle_connection_refused(&peer_id), Ok(()));
    assert_eq!(
        connmgr.events.front(),
        Some(&types::ConnectionManagerEvent::Behaviour(
            types::BehaviourEvent::ConnectionError {
                address: Multiaddr::empty(),
                error: P2pError::DialError(DialError::IoError(
                    std::io::ErrorKind::ConnectionRefused,
                )),
            },
        )),
    );
}

#[tokio::test]
async fn handle_connection_closed() {
    let mut connmgr = ConnectionManager::new();

    // unknown peer
    assert_eq!(
        connmgr.handle_dialer_connection_established(&PeerId::random()),
        Err(P2pError::PeerError(PeerError::PeerDoesntExist))
    );

    // known connection
    let peer_id = PeerId::random();

    connmgr.connections.insert(
        peer_id,
        types::Connection::new(Multiaddr::empty(), types::ConnectionState::Dialing, None),
    );
    assert_eq!(connmgr.handle_connection_closed(&peer_id), Ok(()));
    assert_eq!(
        connmgr.events.front(),
        Some(&types::ConnectionManagerEvent::Behaviour(
            types::BehaviourEvent::ConnectionClosed { peer_id },
        )),
    );
    connmgr.events.clear();
}

#[tokio::test]
async fn close_connection() {
    let mut connmgr = ConnectionManager::new();

    // unknown peer
    assert_eq!(
        connmgr.handle_dialer_connection_established(&PeerId::random()),
        Err(P2pError::PeerError(PeerError::PeerDoesntExist))
    );

    // known connection
    let peer_id = PeerId::random();

    connmgr.connections.insert(
        peer_id,
        types::Connection::new(Multiaddr::empty(), types::ConnectionState::Dialing, None),
    );
    assert_eq!(connmgr.close_connection(&peer_id), Ok(()));
    assert_eq!(
        connmgr.events.front(),
        Some(&types::ConnectionManagerEvent::Control(
            types::ControlEvent::CloseConnection { peer_id },
        )),
    );
    assert!(std::matches!(
        connmgr.connections.get(&peer_id).unwrap().state(),
        types::ConnectionState::Closing
    ));
    connmgr.events.clear();

    // connection already in the state of being closed, no event is emitted
    assert_eq!(connmgr.close_connection(&peer_id), Ok(()));
    assert_eq!(connmgr.events.front(), None);
}

#[tokio::test]
async fn banned_peer() {
    let mut connmgr = ConnectionManager::new();

    // known connection
    let peer_id = PeerId::random();

    connmgr.connections.insert(
        peer_id,
        types::Connection::new(Multiaddr::empty(), types::ConnectionState::Dialing, None),
    );
    connmgr.handle_banned_peer(peer_id);
    assert_eq!(
        connmgr.events.front(),
        Some(&types::ConnectionManagerEvent::Behaviour(
            types::BehaviourEvent::ConnectionError {
                address: Multiaddr::empty(),
                error: P2pError::PeerError(PeerError::BannedPeer(peer_id.to_string())),
            },
        )),
    );
}
