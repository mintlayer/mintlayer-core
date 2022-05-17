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
    error::{self, Libp2pError, P2pError, ProtocolError},
    net::libp2p::backend::{Backend, PendingState},
};
use futures::StreamExt;
use libp2p::{core::connection::ConnectedPoint, swarm::DialError, PeerId};
use logging::log;

impl Backend {
    pub async fn on_connection_established(
        &mut self,
        peer_id: PeerId,
        endpoint: ConnectedPoint,
    ) -> error::Result<()> {
        match endpoint {
            ConnectedPoint::Dialer { .. } => {
                log::trace!("connection established (dialer), peer id {:?}", peer_id);

                match self.pending_conns.remove(&peer_id) {
                    Some(PendingState::Dialed { tx }) => {
                        self.pending_conns.insert(peer_id, PendingState::OutboundAccepted { tx });
                        Ok(())
                    }
                    Some(state) => {
                        // TODO: ban peer?
                        log::error!(
                            "connection state is invalid. Expected `Dialed`, got {:?}",
                            state
                        );
                        Err(P2pError::ProtocolError(ProtocolError::InvalidState))
                    }
                    None => {
                        log::error!("peer {:?} does not exist", peer_id);
                        Err(P2pError::PeerDoesntExist)
                    }
                }
            }
            ConnectedPoint::Listener {
                local_addr: _,
                send_back_addr,
            } => {
                log::trace!("connection established (listener), peer id {:?}", peer_id);

                match self.pending_conns.remove(&peer_id) {
                    Some(state) => {
                        // TODO: is this an actual error?
                        log::error!(
                            "peer {:?} already has active connection, state: {:?}!",
                            peer_id,
                            state
                        );
                        Err(P2pError::ProtocolError(ProtocolError::InvalidState))
                    }
                    None => {
                        self.pending_conns.insert(
                            peer_id,
                            PendingState::InboundAccepted {
                                addr: send_back_addr,
                            },
                        );
                        Ok(())
                    }
                }
            }
        }
    }

    pub async fn on_outgoing_connection_error(
        &mut self,
        peer_id: Option<PeerId>,
        error: DialError,
    ) -> error::Result<()> {
        if let Some(peer_id) = peer_id {
            match self.pending_conns.remove(&peer_id) {
                Some(PendingState::Dialed { tx } | PendingState::OutboundAccepted { tx }) => {
                    tx.send(Err(P2pError::SocketError(
                        std::io::ErrorKind::ConnectionRefused,
                    )))
                    .map_err(|_| P2pError::ChannelClosed)
                }
                _ => {
                    // TODO: report to swarm manager?
                    log::debug!("connection failed for peer {:?}: {:?}", peer_id, error);
                    Err(P2pError::Libp2pError(Libp2pError::DialError(
                        error.to_string(),
                    )))
                }
            }
        } else {
            log::error!("unhandled connection error: {:#?}", error);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::libp2p::{backend, proto::util};
    use libp2p::{core::connection::Endpoint, Multiaddr, PeerId};
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn connection_established_dialer_valid() {
        let (mut backend, _, _, _, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
        )
        .await;
        let (tx, rx) = oneshot::channel();
        let peer_id = PeerId::random();
        backend.pending_conns.insert(peer_id, PendingState::Dialed { tx });

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
            backend.pending_conns.remove(&peer_id),
            Some(backend::PendingState::OutboundAccepted { .. })
        ));
    }

    #[tokio::test]
    async fn connection_established_dialer_invalid_state() {
        let (mut backend, _, _, _, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
        )
        .await;
        let (tx, rx) = oneshot::channel();
        let peer_id = PeerId::random();
        backend.pending_conns.insert(peer_id, PendingState::OutboundAccepted { tx });

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
            Err(P2pError::ProtocolError(ProtocolError::InvalidState))
        );

        backend.pending_conns.insert(
            peer_id,
            PendingState::InboundAccepted {
                addr: Multiaddr::empty(),
            },
        );
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
            Err(P2pError::ProtocolError(ProtocolError::InvalidState))
        );
    }

    #[tokio::test]
    async fn connection_established_dialer_peer_doesnt_exist() {
        let (mut backend, _, _, _, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
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
            Err(P2pError::PeerDoesntExist)
        );
    }

    #[tokio::test]
    async fn connection_established_listener_valid() {
        let (mut backend, _, _, _, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
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
            backend.pending_conns.remove(&peer_id),
            Some(backend::PendingState::InboundAccepted { .. })
        ));
    }

    #[tokio::test]
    async fn connection_established_listener_already_exists() {
        let (mut backend, _, _, _, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
        )
        .await;

        let peer_id = PeerId::random();
        backend.pending_conns.insert(
            peer_id,
            backend::PendingState::InboundAccepted {
                addr: Multiaddr::empty(),
            },
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
            Err(P2pError::ProtocolError(ProtocolError::InvalidState))
        );
    }

    #[tokio::test]
    async fn outgoing_error_inbound_exists() {
        let (mut backend, _, _, _, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
        )
        .await;
    }

    #[tokio::test]
    async fn outgoing_error_peer_id_none() {
        let (mut backend, _, _, _, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
        )
        .await;

        assert_eq!(
            backend.on_outgoing_connection_error(None, DialError::LocalPeerId).await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn outgoing_error_dialed_exists() {
        let (mut backend, _, _, _, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
        )
        .await;
        let peer_id = PeerId::random();
        let (tx, mut rx) = oneshot::channel();
        backend.pending_conns.insert(peer_id, backend::PendingState::Dialed { tx });

        assert_eq!(
            backend.on_outgoing_connection_error(Some(peer_id), DialError::Banned,).await,
            Ok(())
        );

        if let Err(P2pError::SocketError(std::io::ErrorKind::ConnectionRefused)) =
            rx.try_recv().unwrap()
        {
        } else {
            panic!("invalid event received, expected `ConnectionRefused`");
        }
    }

    #[tokio::test]
    async fn outgoing_error_outbound_exists() {
        let (mut backend, _, _, _, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
        )
        .await;
        let peer_id = PeerId::random();
        let (tx, mut rx) = oneshot::channel();
        backend
            .pending_conns
            .insert(peer_id, backend::PendingState::OutboundAccepted { tx });

        assert_eq!(
            backend.on_outgoing_connection_error(Some(peer_id), DialError::Aborted,).await,
            Ok(())
        );

        if let Err(P2pError::SocketError(std::io::ErrorKind::ConnectionRefused)) =
            rx.try_recv().unwrap()
        {
        } else {
            panic!("invalid event received, expected `ConnectionRefused`");
        }
    }

    #[tokio::test]
    async fn outgoing_error_peer_doesnt_exist() {
        let (mut backend, _, _, _, _) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
        )
        .await;
        assert_eq!(
            backend
                .on_outgoing_connection_error(Some(PeerId::random()), DialError::NoAddresses,)
                .await,
            Err(P2pError::Libp2pError(Libp2pError::DialError(
                "Dial error: no addresses for peer.".to_string()
            )))
        );
    }
}
