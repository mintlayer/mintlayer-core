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
    error::{P2pError, PeerError, ProtocolError},
    net::libp2p::{backend::Backend, types},
};
use libp2p::identify::IdentifyEvent;
use logging::log;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::libp2p::{backend, behaviour, proto::util, types::ConnectivityEvent};
    use libp2p::{
        identify::IdentifyInfo, identity, swarm::ConnectionHandlerUpgrErr, Multiaddr, PeerId,
    };

    fn make_empty_info() -> IdentifyInfo {
        IdentifyInfo {
            public_key: identity::Keypair::generate_ed25519().public(),
            protocol_version: "".to_string(),
            agent_version: "".to_string(),
            listen_addrs: vec![],
            protocols: vec![],
            observed_addr: Multiaddr::empty(),
        }
    }

    #[tokio::test]
    async fn test_pushed() {
        let config = common::chain::config::create_mainnet();
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend, _, _, _, _) = util::make_libp2p(config, addr, &[]).await;

        assert_eq!(
            backend
                .on_identify_event(IdentifyEvent::Pushed {
                    peer_id: PeerId::random()
                })
                .await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn test_sent() {
        let config = common::chain::config::create_mainnet();
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend, _, _, _, _) = util::make_libp2p(config, addr, &[]).await;

        assert_eq!(
            backend
                .on_identify_event(IdentifyEvent::Sent {
                    peer_id: PeerId::random()
                })
                .await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn test_error_unconnected() {
        let config = common::chain::config::create_mainnet();
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend, _, mut conn_rx, _, _) = util::make_libp2p(config, addr, &[]).await;

        assert_eq!(
            backend
                .on_identify_event(IdentifyEvent::Error {
                    peer_id: PeerId::random(),
                    error: ConnectionHandlerUpgrErr::Timeout,
                })
                .await,
            Ok(())
        );
        assert_eq!(
            conn_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        );
    }

    #[tokio::test]
    async fn test_error_connected() {
        let config = common::chain::config::create_mainnet();
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend1, _, mut conn_rx, _, _) =
            util::make_libp2p(config.clone(), addr.clone(), &[]).await;

        let addr2: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend2, _, _, _, _) = util::make_libp2p(config, addr2, &[]).await;

        util::connect_swarms::<behaviour::Libp2pBehaviour, behaviour::Libp2pBehaviour>(
            addr,
            &mut backend1.swarm,
            &mut backend2.swarm,
        )
        .await;

        assert_eq!(
            backend1
                .on_identify_event(IdentifyEvent::Error {
                    peer_id: *backend2.swarm.local_peer_id(),
                    error: ConnectionHandlerUpgrErr::Timeout,
                })
                .await,
            Ok(())
        );

        if let Ok(types::ConnectivityEvent::Error { peer_id, error }) = conn_rx.try_recv() {
            assert_eq!(peer_id, *backend2.swarm.local_peer_id());
            assert!(std::matches!(error, P2pError::ConnectionError(_)));
        }
    }

    #[tokio::test]
    async fn test_received_peer_doesnt_exist() {
        let config = common::chain::config::create_mainnet();
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend, _, _, _, _) = util::make_libp2p(config, addr, &[]).await;

        assert_eq!(
            backend
                .on_identify_event(IdentifyEvent::Received {
                    peer_id: PeerId::random(),
                    info: make_empty_info(),
                })
                .await,
            Err(P2pError::PeerError(PeerError::PeerDoesntExist)),
        );
    }

    #[tokio::test]
    async fn test_received_inbound_invalid_state() {
        let config = common::chain::config::create_mainnet();
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend, _, _, _, _) = util::make_libp2p(config, addr, &[]).await;

        let peer_id = PeerId::random();
        backend
            .pending_conns
            .insert(peer_id, backend::PendingState::Dialed(Multiaddr::empty()));

        assert_eq!(
            backend
                .on_identify_event(IdentifyEvent::Received {
                    peer_id,
                    info: make_empty_info(),
                })
                .await,
            Err(P2pError::ProtocolError(ProtocolError::InvalidState(
                "Dialed",
                "InboundAccepted/OutboundAccepted"
            ))),
        );
    }

    #[tokio::test]
    async fn test_received_outbound_accepted() {
        let config = common::chain::config::create_mainnet();
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend, _cmd_tx, mut conn_rx, _pubsub_rx, _sync_rx) =
            util::make_libp2p(config, addr, &[]).await;

        let peer_id = PeerId::random();
        backend.pending_conns.insert(
            peer_id,
            backend::PendingState::OutboundAccepted(Multiaddr::empty()),
        );

        assert_eq!(
            backend
                .on_identify_event(IdentifyEvent::Received {
                    peer_id,
                    info: make_empty_info(),
                })
                .await,
            Ok(())
        );

        if let Ok(ConnectivityEvent::ConnectionAccepted { peer_info, addr: _ }) = conn_rx.try_recv()
        {
            let other = make_empty_info();
            assert!(
                peer_info.protocol_version == other.protocol_version
                    && peer_info.agent_version == other.agent_version
                    && peer_info.listen_addrs == other.listen_addrs
                    && peer_info.protocols == other.protocols
                    && peer_info.observed_addr == other.observed_addr
            );
        }
    }

    #[tokio::test]
    async fn test_received_inbound_accepted() {
        let config = common::chain::config::create_mainnet();
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (mut backend, _, mut conn_rx, _, _) = util::make_libp2p(config, addr, &[]).await;

        let peer_id = PeerId::random();
        backend.pending_conns.insert(
            peer_id,
            backend::PendingState::InboundAccepted(Multiaddr::empty()),
        );

        assert_eq!(
            backend
                .on_identify_event(IdentifyEvent::Received {
                    peer_id,
                    info: make_empty_info(),
                })
                .await,
            Ok(())
        );
        assert!(std::matches!(
            conn_rx.try_recv(),
            Ok(types::ConnectivityEvent::IncomingConnection {
                peer_info: _,
                addr: _,
            })
        ));
    }
}
