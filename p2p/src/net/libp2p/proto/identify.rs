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
    net::libp2p::{
        backend::{Backend, PendingState},
        types,
    },
};
use libp2p::identify::IdentifyEvent;
use logging::log;

impl Backend {
    pub async fn on_identify_event(&mut self, event: IdentifyEvent) -> crate::Result<()> {
        match event {
            IdentifyEvent::Error { peer_id, error } => {
                if !self.swarm.is_connected(&peer_id) {
                    return Ok(());
                }

                log::error!(
                    "libp2p-identify error occurred with connected peer ({:?}): {:?}",
                    peer_id,
                    error
                );

                self.conn_tx
                    .send(types::ConnectivityEvent::Error {
                        peer_id,
                        error: error.into(),
                    })
                    .await
                    .map_err(P2pError::from)
            }
            IdentifyEvent::Sent { peer_id } => {
                log::debug!("identify info sent to peer {:?}", peer_id);
                Ok(())
            }
            IdentifyEvent::Pushed { peer_id } => {
                log::debug!("identify info pushed to peer {:?}", peer_id);
                Ok(())
            }
            IdentifyEvent::Received { peer_id, info } => {
                // TODO: update swarm manager?
                if self.established_conns.contains(&peer_id) {
                    log::trace!("peer {:?} resent their info: {:#?}", peer_id, info);
                    return Ok(());
                }

                match self.pending_conns.remove(&peer_id) {
                    None => {
                        log::error!("pending connection for peer {:?} does not exist", peer_id);
                        Err(P2pError::PeerError(PeerError::PeerDoesntExist))
                    }
                    Some(PendingState::Dialed { tx: _ }) => {
                        // TODO: report peer id to swarm manager?
                        log::error!("received peer info before connection was established");
                        Err(P2pError::ProtocolError(ProtocolError::InvalidState(
                            "Dialed",
                            "InboundAccepted/OutboundAccepted",
                        )))
                    }
                    Some(PendingState::OutboundAccepted { tx }) => {
                        self.established_conns.insert(peer_id);
                        tx.send(Ok(info)).map_err(|_| P2pError::ChannelClosed)
                    }
                    Some(PendingState::InboundAccepted { addr }) => {
                        self.established_conns.insert(peer_id);
                        self.conn_tx
                            .send(types::ConnectivityEvent::IncomingConnection {
                                addr,
                                peer_info: Box::new(info),
                            })
                            .await
                            .map_err(|_| P2pError::ChannelClosed)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::libp2p::{backend, proto::util};
    use libp2p::{
        identify::IdentifyInfo, identity, swarm::ConnectionHandlerUpgrErr, Multiaddr, PeerId,
    };
    use tokio::sync::oneshot;

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

        util::connect_swarms::<types::ComposedBehaviour, types::ComposedBehaviour>(
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
        let (tx, _) = oneshot::channel();

        let peer_id = PeerId::random();
        backend.pending_conns.insert(peer_id, backend::PendingState::Dialed { tx });

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
        let (mut backend, _, _conn_rx, _, _) = util::make_libp2p(config, addr, &[]).await;
        let (tx, mut rx) = oneshot::channel();

        let peer_id = PeerId::random();
        backend
            .pending_conns
            .insert(peer_id, backend::PendingState::OutboundAccepted { tx });

        assert_eq!(
            backend
                .on_identify_event(IdentifyEvent::Received {
                    peer_id,
                    info: make_empty_info(),
                })
                .await,
            Ok(())
        );

        if let Ok(inner) = rx.try_recv().unwrap() {
            let other = make_empty_info();
            assert!(
                inner.protocol_version == other.protocol_version
                    && inner.agent_version == other.agent_version
                    && inner.listen_addrs == other.listen_addrs
                    && inner.protocols == other.protocols
                    && inner.observed_addr == other.observed_addr
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
            backend::PendingState::InboundAccepted {
                addr: Multiaddr::empty(),
            },
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
        assert_eq!(
            conn_rx.try_recv(),
            Ok(types::ConnectivityEvent::ConnectionAccepted {
                peer_info: Box::new(make_empty_info()),
            }),
        );
    }
}
