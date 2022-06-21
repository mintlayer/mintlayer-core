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
        backend::Backend,
        types::{self, PendingState},
        DialError,
    },
};
use libp2p::{core::connection::ConnectedPoint, swarm::DialError as Libp2pDialError, PeerId};
use logging::log;

impl Backend {
    pub async fn on_connection_established(
        &mut self,
        peer_id: PeerId,
        endpoint: ConnectedPoint,
    ) -> crate::Result<()> {
        match endpoint {
            ConnectedPoint::Dialer { .. } => {
                log::trace!("connection established (dialer), peer id {:?}", peer_id);

                match self.swarm.behaviour_mut().pending_conns.remove(&peer_id) {
                    Some(PendingState::Dialed(addr)) => {
                        self.swarm
                            .behaviour_mut()
                            .pending_conns
                            .insert(peer_id, PendingState::OutboundAccepted(addr));
                        Ok(())
                    }
                    Some(PendingState::InboundAccepted(_addr)) => {
                        // TODO: ban peer?
                        log::error!(
                            "connection state is invalid. Expected `Dialed`, got `OutboundAccepted`",
                        );
                        Err(P2pError::ProtocolError(ProtocolError::InvalidState(
                            "InboundAccepted",
                            "Dialed",
                        )))
                    }
                    Some(PendingState::OutboundAccepted(_addr)) => {
                        // TODO: ban peer?
                        log::error!(
                            "connection state is invalid. Expected `Dialed`, got `OutboundAccepted`",
                        );
                        Err(P2pError::ProtocolError(ProtocolError::InvalidState(
                            "OutboundAccepted",
                            "Dialed",
                        )))
                    }
                    None => {
                        log::error!("peer {} does not exist", peer_id);
                        Err(P2pError::PeerError(PeerError::PeerDoesntExist))
                    }
                }
            }
            ConnectedPoint::Listener {
                local_addr: _,
                send_back_addr,
            } => {
                log::trace!("connection established (listener), peer id {:?}", peer_id);

                match self.swarm.behaviour_mut().pending_conns.remove(&peer_id) {
                    Some(state) => {
                        // TODO: is this an actual error?
                        log::error!(
                            "peer {:?} already has active connection, state: {:?}!",
                            peer_id,
                            state
                        );
                        Err(P2pError::ProtocolError(ProtocolError::InvalidState("", "")))
                    }
                    None => {
                        self.swarm
                            .behaviour_mut()
                            .pending_conns
                            .insert(peer_id, PendingState::InboundAccepted(send_back_addr));
                        Ok(())
                    }
                }
            }
        }
    }

    pub async fn on_outgoing_connection_error(
        &mut self,
        peer_id: Option<PeerId>,
        error: Libp2pDialError,
    ) -> crate::Result<()> {
        if let Some(peer_id) = peer_id {
            match self.swarm.behaviour_mut().pending_conns.remove(&peer_id) {
                Some(PendingState::Dialed(addr) | PendingState::OutboundAccepted(addr)) => self
                    .conn_tx
                    .send(types::ConnectivityEvent::ConnectionError {
                        addr,
                        error: P2pError::DialError(DialError::IoError(
                            std::io::ErrorKind::ConnectionRefused,
                        )),
                    })
                    .await
                    .map_err(|_| P2pError::ChannelClosed),
                _ => {
                    // TODO: report to swarm manager?
                    log::debug!("connection failed for peer {:?}: {:?}", peer_id, error);
                    Err(error.into())
                }
            }
        } else {
            log::error!("unhandled connection error: {:#?}", error);
            Ok(())
        }
    }

    pub async fn on_connection_closed(&mut self, peer_id: PeerId) -> crate::Result<()> {
        self.swarm.behaviour_mut().established_conns.remove(&peer_id);
        self.conn_tx
            .send(types::ConnectivityEvent::ConnectionClosed { peer_id })
            .await
            .map_err(|_| P2pError::ChannelClosed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::libp2p::{backend, proto::util, types::ConnectivityEvent};
    use libp2p::{core::connection::Endpoint, Multiaddr, PeerId};

    #[tokio::test]
    async fn connection_established_dialer_valid() {
        let (mut backend, _cmd_tx, _conn_rx, _pubsub_rx, _sync_rx) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
        )
        .await;
        let peer_id = PeerId::random();
        backend.pending_conns.insert(peer_id, PendingState::Dialed(Multiaddr::empty()));

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
            Some(backend::PendingState::OutboundAccepted(_))
        ));
    }

    #[tokio::test]
    async fn connection_established_dialer_invalid_state() {
        let (mut backend, _cmd_tx, _conn_rx, _pubsub_rx, _sync_rx) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
        )
        .await;
        let peer_id = PeerId::random();
        backend
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
        let (mut backend, _cmd_tx, _conn_rx, _pubsub_rx, _sync_rx) = util::make_libp2p(
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
            Err(P2pError::PeerError(PeerError::PeerDoesntExist))
        );
    }

    #[tokio::test]
    async fn connection_established_listener_valid() {
        let (mut backend, _cmd_tx, _conn_rx, _pubsub_rx, _sync_rx) = util::make_libp2p(
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
        let (mut backend, _cmd_tx, _conn_rx, _pubsub_rx, _sync_rx) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
        )
        .await;

        let peer_id = PeerId::random();
        backend.pending_conns.insert(
            peer_id,
            backend::PendingState::InboundAccepted(Multiaddr::empty()),
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
    async fn outgoing_error_inbound_exists() {
        let (_backend, _cmd_tx, _conn_rx, _pubsub_rx, _sync_rx) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
        )
        .await;
    }

    #[tokio::test]
    async fn outgoing_error_peer_id_none() {
        let (mut backend, _cmd_tx, _conn_rx, _pubsub_rx, _sync_rx) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
        )
        .await;

        assert_eq!(
            backend.on_outgoing_connection_error(None, Libp2pDialError::LocalPeerId).await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn outgoing_error_dialed_exists() {
        let (mut backend, _cmd_tx, mut _conn_rx, _pubsub_rx, _sync_rx) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
        )
        .await;
        let peer_id = PeerId::random();
        backend
            .pending_conns
            .insert(peer_id, backend::PendingState::Dialed(Multiaddr::empty()));

        assert_eq!(
            backend
                .on_outgoing_connection_error(Some(peer_id), Libp2pDialError::Banned,)
                .await,
            Ok(())
        );

        match _conn_rx.try_recv() {
            Ok(ConnectivityEvent::ConnectionError {
                addr: _,
                error:
                    P2pError::DialError(DialError::IoError(std::io::ErrorKind::ConnectionRefused)),
            }) => {}
            _ => panic!("invalid event received, expected `ConnectionRefused`"),
        }
    }

    #[tokio::test]
    async fn outgoing_error_outbound_exists() {
        let (mut backend, _cmd_tx, _conn_rx, _pubsub_rx, _sync_rx) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
        )
        .await;
        let peer_id = PeerId::random();
        backend.pending_conns.insert(
            peer_id,
            backend::PendingState::OutboundAccepted(Multiaddr::empty()),
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
        let (mut backend, _cmd_tx, _conn_rx, _pubsub_rx, _sync_rx) = util::make_libp2p(
            common::chain::config::create_mainnet(),
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
        )
        .await;
        assert_eq!(
            backend
                .on_outgoing_connection_error(Some(PeerId::random()), Libp2pDialError::NoAddresses)
                .await,
            Err(P2pError::DialError(DialError::NoAddresses))
        );
    }
}
