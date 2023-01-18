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

//! Peer manager
//!
//! TODO
//!
//!

#![allow(rustdoc::private_intra_doc_links)]

pub mod peerdb;

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::{mpsc, oneshot};

use chainstate::ban_score::BanScore;
use common::{chain::ChainConfig, primitives::semver::SemVer};
use logging::log;
use utils::ensure;

use crate::{
    config::P2pConfig,
    error::{P2pError, PeerError, ProtocolError},
    event::{PeerManagerEvent, SyncControlEvent},
    message::{AddrListRequest, AddrListResponse, PeerManagerRequest, PeerManagerResponse},
    net::{
        self,
        default_backend::transport::TransportAddress,
        types::{PeerInfo, Role},
        AsBannableAddress, ConnectivityService, NetworkingService,
    },
    types::peer_address::PeerAddress,
};

/// Maximum number of connections the [`PeerManager`] is allowed to have open
const MAX_ACTIVE_CONNECTIONS: usize = 128;

/// Lower bound for how often [`PeerManager::heartbeat()`] is called
const PEER_MGR_HEARTBEAT_INTERVAL_MIN: Duration = Duration::from_secs(5);
/// Upper bound for how often [`PeerManager::heartbeat()`] is called
const PEER_MGR_HEARTBEAT_INTERVAL_MAX: Duration = Duration::from_secs(30);

pub struct PeerManager<T>
where
    T: NetworkingService,
{
    /// Chain configuration.
    chain_config: Arc<ChainConfig>,

    /// P2P configuration.
    _p2p_config: Arc<P2pConfig>,

    /// Handle for sending/receiving connectivity events
    peer_connectivity_handle: T::ConnectivityHandle,

    /// RX channel for receiving control events
    rx_peer_manager: mpsc::UnboundedReceiver<PeerManagerEvent<T>>,

    /// TX channel for sending events to SyncManager
    tx_sync: mpsc::UnboundedSender<SyncControlEvent<T>>,

    /// Hashmap of pending outbound connections
    pending: HashMap<T::Address, Option<oneshot::Sender<crate::Result<()>>>>,

    /// Peer database
    peerdb: peerdb::PeerDb<T>,

    last_heartbeat: Instant,
}

impl<T> PeerManager<T>
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    pub fn new(
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        handle: T::ConnectivityHandle,
        rx_peer_manager: mpsc::UnboundedReceiver<PeerManagerEvent<T>>,
        tx_sync: mpsc::UnboundedSender<SyncControlEvent<T>>,
    ) -> crate::Result<Self> {
        Ok(Self {
            peer_connectivity_handle: handle,
            rx_peer_manager,
            tx_sync,
            peerdb: peerdb::PeerDb::new(Arc::clone(&p2p_config))?,
            pending: HashMap::new(),
            chain_config,
            _p2p_config: p2p_config,
            last_heartbeat: Instant::now(),
        })
    }

    /// Verify software version compatibility
    ///
    /// Make sure that local and remote peer have the same software version
    fn validate_version(&self, version: &SemVer) -> bool {
        // TODO: handle upgrades of versions
        version == self.chain_config.version()
    }

    /// Handle connection established event
    ///
    /// The event is received from the networking backend and it's either a result of an incoming
    /// connection from a remote peer or a response to an outbound connection that was initiated
    /// by the node as result of the peer manager maintenance.
    fn accept_connection(
        &mut self,
        address: T::Address,
        role: Role,
        info: PeerInfo<T::PeerId>,
        _receiver_address: Option<PeerAddress>,
    ) -> crate::Result<()> {
        // TODO: Handle receiver_address

        let peer_id = info.peer_id;

        ensure!(
            info.network == *self.chain_config.magic_bytes(),
            P2pError::ProtocolError(ProtocolError::DifferentNetwork(
                *self.chain_config.magic_bytes(),
                info.network,
            ))
        );
        ensure!(
            self.validate_version(&info.version),
            P2pError::ProtocolError(ProtocolError::InvalidVersion(
                *self.chain_config.version(),
                info.version
            ))
        );
        ensure!(
            !self.peerdb.is_active_peer(&info.peer_id),
            P2pError::PeerError(PeerError::PeerAlreadyExists),
        );
        ensure!(
            !self.peerdb.is_address_connected(&address),
            P2pError::PeerError(PeerError::PeerAlreadyExists),
        );

        log::debug!("peer {peer_id} connected, address {address:?}, {info}");
        self.peerdb.peer_connected(address, role, info);
        self.tx_sync.send(SyncControlEvent::Connected(peer_id)).map_err(P2pError::from)
    }

    /// Validate inbound peer connection
    ///
    /// As inbound connections are received, they are pre-validated before passed
    /// on to the generic connection validator as these connections haven't gone
    /// through the same validation as outbound connections.
    ///
    /// This function verifies that neither address the nor the peer ID are on the
    /// list of banned IPs/peer IDs. It also checks that the maximum number of
    /// connections `PeerManager` is configured to have has not been reached.
    fn accept_inbound_connection(
        &mut self,
        address: T::Address,
        info: net::types::PeerInfo<T::PeerId>,
        receiver_address: Option<PeerAddress>,
    ) -> crate::Result<()> {
        log::debug!("validate inbound connection, inbound address {address:?}");

        ensure!(
            !self.peerdb.is_active_peer(&info.peer_id),
            P2pError::PeerError(PeerError::PeerAlreadyExists),
        );

        let bannable_address = address.as_bannable();
        ensure!(
            !self.peerdb.is_address_banned(&bannable_address),
            P2pError::PeerError(PeerError::BannedAddress(address.to_string())),
        );

        // if the maximum number of connections is reached, the connection cannot be
        // accepted even if it's valid. The peer is still reported to the PeerDb which
        // knows of all peers and later on if the number of connections falls below
        // the desired threshold, `PeerManager::heartbeat()` may connect to this peer.
        if self.peerdb.active_peer_count() >= MAX_ACTIVE_CONNECTIONS {
            return Err(P2pError::PeerError(PeerError::TooManyPeers));
        }

        self.accept_connection(address, Role::Inbound, info, receiver_address)
    }

    /// Close connection to a remote peer
    ///
    /// The decision to close the connection is made either by the user via RPC
    /// or by the [`PeerManager::heartbeat()`] function which has decided to cull
    /// this connection in favor of another potential connection.
    fn close_connection(&mut self, peer_id: T::PeerId) -> crate::Result<()> {
        // The backend is always sending ConnectionClosed event when somebody disconnects, ensure that the peer is active
        if self.peerdb.is_active_peer(&peer_id) {
            log::debug!("connection closed for peer {peer_id}");

            self.tx_sync.send(SyncControlEvent::Disconnected(peer_id))?;

            self.peerdb.peer_disconnected(&peer_id);
        }
        Ok(())
    }

    /// Adjust peer score
    ///
    /// If after adjustment the peer score is more than the ban threshold, the peer is banned
    /// which makes the `PeerDb` mark is banned and prevents any further connections with the peer
    /// and also bans the peer in the networking backend.
    async fn adjust_peer_score(&mut self, peer_id: T::PeerId, score: u32) -> crate::Result<()> {
        log::debug!("adjusting score for peer {peer_id}, adjustment {score}");

        if self.peerdb.adjust_peer_score(&peer_id, score) {
            let _ = self.peer_connectivity_handle.disconnect(peer_id).await;
        }

        Ok(())
    }

    /// Handle outbound connection error
    ///
    /// The outbound connection was dialed successfully but the remote either did not respond
    /// (at all or in time) or it didn't support the handshaking which forced the connection closed.
    ///
    /// If the connection was initiated by the user via RPC, inform them that the connection failed.
    /// Inform the [`crate::peer_manager::peerdb::PeerDb`] about the address failure so it knows to
    /// update its own records.
    fn handle_outbound_error(&mut self, address: T::Address, error: P2pError) -> crate::Result<()> {
        if let Some(Some(channel)) = self.pending.remove(&address) {
            channel.send(Err(error)).map_err(|_| P2pError::ChannelClosed)?;
        }

        self.peerdb.report_outbound_failure(address);
        Ok(())
    }

    /// Attempt to establish an outbound connection
    ///
    /// This function doesn't block on the call but sends a command to the
    /// networking backend which then reports at some point in the future
    /// whether the connection failed or succeeded.
    async fn connect(&mut self, address: T::Address) -> crate::Result<()> {
        // TODO: verify that the peer is not already part of our swarm (needs peerdb)
        ensure!(
            !self.pending.contains_key(&address),
            P2pError::PeerError(PeerError::Pending(address.to_string())),
        );

        let bannable_address = address.as_bannable();
        ensure!(
            !self.peerdb.is_address_banned(&bannable_address),
            P2pError::PeerError(PeerError::BannedAddress(address.to_string())),
        );

        self.peer_connectivity_handle.connect(address).await
    }

    /// Maintains the peer manager state.
    ///
    /// `PeerManager::heartbeat()` is called every time a network/control event is received
    /// or the heartbeat timer of the event loop expires. In other words, the peer manager state
    /// is checked and updated at least once every 30 seconds. In high-traffic scenarios the
    /// update interval is clamped to a sensible lower bound. `PeerManager` will keep track of
    /// when it last update its own state and if the time since last update is less than the
    /// configured lower bound, it exits early from the function.
    ///
    /// This function maintains the overall connectivity state of peers by culling
    /// low-reputation peers and establishing new connections with peers that have higher
    /// reputation. It also updates peer scores and forgets those peers that are no longer needed.
    ///
    /// TODO: IP address diversity check?
    /// TODO: exploratory peer connections?
    /// TODO: close connection with low-score peers in favor of peers with higher score?
    ///
    /// The process starts by first checking if the number of active connections is less than
    /// the number of desired connections and there are available peers, the function tries to
    /// establish new connections. After that it updates the peer scores and discards any records
    /// that no longer need to be stored.
    async fn heartbeat(&mut self) -> crate::Result<()> {
        let npeers = std::cmp::min(
            self.peerdb.available_addresses_count(),
            MAX_ACTIVE_CONNECTIONS
                .saturating_sub(self.peerdb.available_addresses_count())
                .saturating_sub(self.pending.len()),
        );

        for _ in 0..npeers {
            if let Some(addr) = self.peerdb.take_best_peer_addr() {
                match self.connect(addr.clone()).await {
                    Ok(_) => {
                        self.pending.insert(addr, None);
                    }
                    Err(err) => {
                        self.peerdb.report_outbound_failure(addr.clone());
                        self.handle_result(None, Err(err)).await?;
                    }
                }
            }
        }

        // TODO: update peer scores

        Ok(())
    }

    async fn handle_incoming_request(
        &mut self,
        _peer_id: T::PeerId,
        request_id: T::PeerRequestId,
        request: PeerManagerRequest,
    ) -> crate::Result<()> {
        match request {
            // TODO: Rework this
            PeerManagerRequest::AddrListRequest(AddrListRequest {}) => {
                let addresses = self.peerdb.known_addresses();

                self.peer_connectivity_handle
                    .send_response(
                        request_id,
                        PeerManagerResponse::AddrListResponse(AddrListResponse::new(addresses)),
                    )
                    .await
            }
        }
    }

    fn handle_incoming_response(
        &mut self,
        _peer_id: T::PeerId,
        _request_id: T::PeerRequestId,
        response: PeerManagerResponse,
    ) -> crate::Result<()> {
        match response {
            // TODO: Rework this
            PeerManagerResponse::AddrListResponse(response) => {
                for address in response.addresses() {
                    if let Some(address) = TransportAddress::from_peer_address(address) {
                        self.peerdb.peer_discovered(&address);
                    }
                }
                Ok(())
            }
        }
    }

    /// Handle the result of a control/network event
    ///
    /// Currently only subsystem/channel-related errors are considered fatal.
    /// Other errors are logged as warnings and `Ok(())` is returned as they should
    /// not disturb the operation of `PeerManager`.
    ///
    /// If an error has ban score greater than zero, the peer score is updated and connection
    /// to that peer is possibly closed if their score crossed the ban threshold.
    ///
    /// # Arguments
    /// `peer_id` - peer ID of the remote peer, if available
    /// `result` - result of the operation that was performed
    pub async fn handle_result(
        &mut self,
        peer_id: Option<T::PeerId>,
        result: crate::Result<()>,
    ) -> crate::Result<()> {
        match result {
            Ok(_) => Ok(()),
            Err(P2pError::ChannelClosed | P2pError::SubsystemFailure) => {
                log::error!("connection lost with subsystem wrapper/p2p subsystem");
                result
            }
            Err(err) => {
                log::warn!("non-fatal error occurred: {err}");

                if let Some(peer_id) = peer_id {
                    log::info!("adjust peer score for peer {peer_id}, reason {err}");
                    return self.adjust_peer_score(peer_id, err.ban_score()).await;
                }

                Ok(())
            }
        }
    }

    /// Runs the `PeerManager` event loop.
    ///
    /// The event loop has three main responsibilities:
    /// - listening to and handling control events from [`crate::sync::SyncManager`]/
    /// [`crate::pubsub::PubSubMessageHandler`]/RPC
    /// - listening to network events
    /// - updating internal state
    ///
    /// After handling an event from one of the aforementioned sources, the event loop
    /// handles the error (if any) and runs the [`PeerManager::heartbeat()`] function
    /// to perform the peer manager maintenance. If the `PeerManager` doesn't receive any events,
    /// [`PEER_MGR_HEARTBEAT_INTERVAL`] defines how often the heartbeat function is called.
    /// This is done to prevent the `PeerManager` from stalling in case the network doesn't
    /// have any events.
    pub async fn run(&mut self) -> crate::Result<void::Void> {
        loop {
            tokio::select! {
                event = self.rx_peer_manager.recv() => match event.ok_or(P2pError::ChannelClosed)? {
                    //
                    // Handle events from an outside controller (rpc, for example) that sets/gets values for PeerManager
                    //
                    PeerManagerEvent::Connect(addr, response) => {
                        log::debug!("try to establish outbound connection to peer at address {addr:?}");

                        let res = self.connect(addr.clone()).await.map(|_| {
                            self.pending.insert(addr.clone(), Some(response));
                        });
                        self.handle_result(None, res).await?;
                    }
                    PeerManagerEvent::Disconnect(peer_id, response) => {
                        log::debug!("disconnect peer {peer_id}");

                        response
                            .send(self.peer_connectivity_handle.disconnect(peer_id).await)
                            .map_err(|_| P2pError::ChannelClosed)?;
                    }
                    PeerManagerEvent::AdjustPeerScore(peer_id, score, response) => {
                        log::debug!("adjust peer {peer_id} score: {score}");

                        response
                            .send(self.adjust_peer_score(peer_id, score).await)
                            .map_err(|_| P2pError::ChannelClosed)?;
                    }
                    PeerManagerEvent::GetPeerCount(response) => {
                        response.send(self.peerdb.active_peer_count()).map_err(|_| P2pError::ChannelClosed)?;
                    }
                    PeerManagerEvent::GetBindAddresses(response) => {
                        let addr = self.peer_connectivity_handle.local_addresses();
                        let addr = addr.await.unwrap_or_default().into_iter().map(|addr| addr.to_string()).collect();
                        response.send(addr).map_err(|_| P2pError::ChannelClosed)?;
                    }
                    PeerManagerEvent::GetConnectedPeers(response) => {
                        let peers = self.peerdb.get_connected_peers();
                        response.send(peers).map_err(|_| P2pError::ChannelClosed)?
                    }
                },
                event = self.peer_connectivity_handle.poll_next() => match event {
                    Ok(event) => match event {
                        net::types::ConnectivityEvent::Request { peer_id, request_id, request } => {
                            self.handle_incoming_request(peer_id, request_id, request).await?;
                        },
                        net::types::ConnectivityEvent::Response { peer_id, request_id, response } => {
                            self.handle_incoming_response(peer_id, request_id, response)?;
                        },
                        net::types::ConnectivityEvent::InboundAccepted { address, peer_info, receiver_address } => {
                            let peer_id = peer_info.peer_id;

                            match self.accept_inbound_connection(address, peer_info, receiver_address) {
                                Ok(_) => {},
                                Err(P2pError::ChannelClosed) => return Err(P2pError::ChannelClosed),
                                Err(P2pError::PeerError(err)) => {
                                    log::warn!("peer error for peer {peer_id}: {err}");
                                    self.peer_connectivity_handle.disconnect(peer_id).await?;
                                }
                                Err(P2pError::ProtocolError(err)) => {
                                    log::warn!("peer error for peer {peer_id}: {err}");
                                    self.adjust_peer_score(peer_id, err.ban_score()).await?;
                                }
                                Err(err) => {
                                    log::error!("unknown error for peer {peer_id}: {err}");
                                }
                            }
                        }
                        net::types::ConnectivityEvent::OutboundAccepted { address, peer_info, receiver_address } => {
                            let peer_id = peer_info.peer_id;
                            let res = self.accept_connection(address.clone(), Role::Outbound, peer_info, receiver_address);
                            self.handle_result(Some(peer_id), res).await?;

                            match self.pending.remove(&address) {
                                Some(Some(channel)) => channel.send(Ok(())).map_err(|_| P2pError::ChannelClosed)?,
                                Some(None) => {},
                                None => log::error!("connection accepted but it's not pending?"),
                            }
                        }
                        net::types::ConnectivityEvent::ConnectionClosed { peer_id } => {
                            let res = self.close_connection(peer_id);
                            self.handle_result(Some(peer_id), res).await?;
                        }
                        net::types::ConnectivityEvent::ConnectionError { address, error } => {
                            let res = self.handle_outbound_error(address, error);
                            self.handle_result(None, res).await?;
                        }
                        net::types::ConnectivityEvent::Misbehaved { peer_id, error } => {
                            let res = self.adjust_peer_score(peer_id, error.ban_score()).await;
                            self.handle_result(Some(peer_id), res).await?;
                        }
                    }
                    Err(err) => {
                        log::error!("failed to read network event: {err:?}");
                        self.handle_result(None, Err(err)).await?;
                    }
                },
                _event = tokio::time::sleep(PEER_MGR_HEARTBEAT_INTERVAL_MAX) => {}
            }

            // finally update peer manager state
            let now = Instant::now();
            if now.duration_since(self.last_heartbeat) > PEER_MGR_HEARTBEAT_INTERVAL_MIN {
                self.heartbeat().await?;
                self.last_heartbeat = now;
            }
        }
    }
}

#[cfg(test)]
mod tests;
