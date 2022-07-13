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

//! Peer manager
//!
//! TODO
//!
//!

#![allow(rustdoc::private_intra_doc_links)]
use crate::{
    error::{P2pError, PeerError, ProtocolError},
    event,
    net::{self, ConnectivityService, NetworkingService},
};
use chainstate::ban_score::BanScore;
use common::{chain::ChainConfig, primitives::semver};
use futures::FutureExt;
use logging::log;
use std::{collections::HashMap, fmt::Debug, str::FromStr, sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};
use utils::ensure;

pub mod peerdb;

/// Maximum number of connections the [`PeerManager`] is allowed to have open
const MAX_ACTIVE_CONNECTIONS: usize = 128;

/// Lower bound for how often [`PeerManager::heartbeat()`] is called
const PEER_MGR_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

pub struct PeerManager<T>
where
    T: NetworkingService,
{
    /// Chain config
    config: Arc<ChainConfig>,

    /// Handle for sending/receiving connectivity events
    handle: T::ConnectivityHandle,

    /// Hashmap for peer information
    peers: HashMap<T::PeerId, peerdb::PeerContext<T>>,

    /// RX channel for receiving control events
    rx_swarm: mpsc::Receiver<event::SwarmEvent<T>>,

    /// TX channel for sending events to SyncManager
    tx_sync: mpsc::Sender<event::SyncControlEvent<T>>,

    /// Hashmap of pending outbound connections
    pending: HashMap<T::Address, Option<oneshot::Sender<crate::Result<()>>>>,

    /// Peer database
    peerdb: peerdb::PeerDb<T>,
}

impl<T> PeerManager<T>
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    <T as NetworkingService>::Address: FromStr,
    <<T as NetworkingService>::Address as FromStr>::Err: Debug,
{
    pub fn new(
        config: Arc<ChainConfig>,
        handle: T::ConnectivityHandle,
        rx_swarm: mpsc::Receiver<event::SwarmEvent<T>>,
        tx_sync: mpsc::Sender<event::SyncControlEvent<T>>,
    ) -> Self {
        Self {
            config,
            handle,
            rx_swarm,
            tx_sync,
            peerdb: peerdb::PeerDb::new(),
            peers: HashMap::with_capacity(MAX_ACTIVE_CONNECTIONS),
            pending: HashMap::new(),
        }
    }

    /// Get mutable reference to the `ConnectivityHandle`
    #[allow(dead_code)]
    fn handle_mut(&mut self) -> &mut T::ConnectivityHandle {
        &mut self.handle
    }

    /// Update the list of known peers or known peer's list of addresses
    fn peer_discovered(&mut self, peers: &[net::types::AddrInfo<T>]) {
        self.peerdb.discover_peers(peers)
    }

    /// Update the list of known peers or known peer's list of addresses
    fn peer_expired(&mut self, peers: &[net::types::AddrInfo<T>]) {
        self.peerdb.expire_peers(peers)
    }

    /// Check is the IP address banned
    fn validate_address(&self, address: &T::Address) -> bool {
        !self.peerdb.is_address_banned(address)
    }

    /// Check is the peer ID banned
    fn validate_peer_id(&self, peer_id: &T::PeerId) -> bool {
        !self.peerdb.is_id_banned(peer_id)
    }

    /// Verify protocol compatibility
    ///
    /// Make sure that remote peer supports the same versions of the protocols that we do
    /// and that they support the mandatory protocols which for now are configured to be:
    ///
    /// - `/meshsub/1.1.0`
    /// - `/meshsub/1.0.0`
    /// - `/ipfs/ping/1.0.0`
    /// - `/ipfs/id/1.0.0`
    /// - `/ipfs/id/push/1.0.0`
    /// - `/mintlayer/sync/0.1.0`
    ///
    /// If any of the procols are missing or if any of them have a different version,
    /// the validation fails and connection must be closed.
    ///
    /// Either peer may support additional protocols which are not known to the other
    /// peer and that is totally fine. As long as the aforementioned protocols with
    /// matching versions are found, the protocol set has been validated successfully.
    // TODO: create generic versions of the protocols when mock interface is supported again
    // TODO: convert `protocols` to a hashset
    // TODO: define better protocol id type
    fn validate_supported_protocols(&self, protocols: &[T::ProtocolId]) -> bool {
        const REQUIRED: &[&str] = &[
            "/meshsub/1.1.0",
            "/meshsub/1.0.0",
            "/ipfs/ping/1.0.0",
            "/ipfs/id/1.0.0",
            "/ipfs/id/push/1.0.0",
            "/mintlayer/sync/0.1.0",
        ];

        for required_proto in REQUIRED {
            if !protocols.iter().any(|proto| &proto.to_string().as_str() == required_proto) {
                return false;
            }
        }

        true
    }

    /// Verify software version compatibility
    ///
    /// Make sure that local and remote peer have the same software version
    fn validate_version(&self, version: &semver::SemVer) -> bool {
        version == self.config.version()
    }

    /// Handle connection established event
    ///
    /// The event is received from the networking backend and it's either a result of an incoming
    /// connection from a remote peer or a response to an outbound connection that was initiated
    /// by the node as result of swarm maintenance.
    async fn accept_connection(&mut self, info: net::types::PeerInfo<T>) -> crate::Result<()> {
        log::debug!("{}", info);

        ensure!(
            info.magic_bytes == *self.config.magic_bytes(),
            P2pError::ProtocolError(ProtocolError::DifferentNetwork(
                *self.config.magic_bytes(),
                info.magic_bytes,
            ))
        );
        ensure!(
            self.validate_version(&info.version),
            P2pError::ProtocolError(ProtocolError::InvalidVersion(
                *self.config.version(),
                info.version
            ))
        );
        ensure!(
            self.validate_supported_protocols(&info.protocols),
            P2pError::ProtocolError(ProtocolError::Incompatible),
        );
        ensure!(
            self.peers.get(&info.peer_id).is_none(),
            P2pError::PeerError(PeerError::PeerAlreadyExists),
        );

        let peer_id = info.peer_id;
        self.peers.insert(
            info.peer_id,
            peerdb::PeerContext {
                _info: info,
                score: 0,
            },
        );
        self.tx_sync
            .send(event::SyncControlEvent::Connected(peer_id))
            .await
            .map_err(P2pError::from)
    }

    /// Validate inbound peer connection
    ///
    /// As inbound connections are received, they are prevalidated before passed
    /// on to the generic connection validator as these connections haven't gone
    /// through the same validation as outbound connections.
    ///
    /// This function verifies that neither address the nor the peer ID are on the
    /// list of banned IPs/peer IDs. It also checks that the maximum number of
    /// connections `PeerManager` is configured to have has not been reached.
    async fn accept_inbound_connection(
        &mut self,
        address: T::Address,
        info: net::types::PeerInfo<T>,
    ) -> crate::Result<()> {
        log::debug!("validate inbound connection, inbound address {}", address);

        ensure!(
            self.validate_address(&address),
            P2pError::PeerError(PeerError::BannedAddress(address.to_string())),
        );
        ensure!(
            self.validate_peer_id(&info.peer_id),
            P2pError::PeerError(PeerError::BannedPeer(info.peer_id.to_string())),
        );

        // if the maximum number of connections is reached, the connection cannot be
        // accepted even if it's valid. The peer is still reported to the PeerDb which
        // knows of all peers and later on if the number of connections falls below
        // the desired threshold, `PeerManager::heartbeat()` may connect to this peer.
        if self.peers.len() >= MAX_ACTIVE_CONNECTIONS {
            // TODO: report this peer to peerdb
            // TODO: close some other connection in favor of this if peerdb knows this
            //       peer and it has higher reputation than some other peer we're currently
            //       connected to?
            self.peerdb.register_peer_info(info);
            // self.handle.reject_connection(info.peer_id).await?;
            return Err(P2pError::PeerError(PeerError::TooManyPeers));
        }

        self.accept_connection(info).await
    }

    /// Close connection to a remote peer
    ///
    /// The decision to close the connection is made either by the user via RPC
    /// or by the [`PeerManager::heartbeat()`] function which has decided to cull
    /// this connection in favor of another potential connection.
    async fn close_connection(&mut self, peer_id: T::PeerId) -> crate::Result<()> {
        log::debug!("connection closed for peer {}", peer_id);

        self.tx_sync.send(event::SyncControlEvent::Disconnected(peer_id)).await?;
        self.peers.remove(&peer_id);
        Ok(())
    }

    /// Adjust peer score
    ///
    /// If after adjustment the peer score is more than the ban threshold, the peer is banned.
    async fn adjust_peer_score(&mut self, peer_id: T::PeerId, score: u32) -> crate::Result<()> {
        log::debug!("adjusting score for peer {}, adjustment {}", peer_id, score);

        let score = if let Some(entry) = self.peers.get_mut(&peer_id) {
            entry.score = entry.score.saturating_add(score);
            entry.score
        } else {
            score
        };

        // TODO: from config
        if score >= 100 {
            self.peerdb.ban_peer(&peer_id);
            return self.handle.ban_peer(peer_id).await;
        }

        Ok(())
    }

    /// Handle outbound connection error
    ///
    /// The outbound connection was dialed successfully but the remote either did not respond
    /// (at all or in time) or it didn't support the handshaking which forced the connection closed.
    ///
    /// If the connection was initiated by the user via RPC, inform them that the connection failed.
    /// Inform the [`crate::swarm::peerdb::PeerDb`] about the address failure so it knows to update its
    /// own records.
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
        ensure!(
            self.validate_address(&address),
            P2pError::PeerError(PeerError::BannedAddress(address.to_string())),
        );

        self.handle.connect(address).await
    }

    /// Maintain the swarm state
    ///
    /// `PeerManager::heartbeat()` is called every time a network/control event is received
    /// or the heartbeat timer of the event loop expires. In other words, the swarm state
    /// is checked and updated at least once every 30 seconds. In high-traffic scenarios the
    /// update interval is clamped to a sensible lower bound. `PeerManager` will keep track of
    /// when it last update its own state and if the time since last update is less than the
    /// configured lower bound, it exits early from the function.
    ///
    /// This function maintains the overall connectivity state of the swarm by culling
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
        // TODO: check when was the last update and exit early if this update is to soon

        let npeers = std::cmp::min(
            self.peerdb.idle_peer_count(),
            MAX_ACTIVE_CONNECTIONS
                .saturating_sub(self.peers.len())
                .saturating_sub(self.pending.len()),
        );

        for _ in 0..npeers {
            if let Some(addr) = self.peerdb.best_peer_addr() {
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

    /// Handle the result of a control/network event
    ///
    /// Currently only subsystem/channel-related errors are considered fatal.
    /// Other errors are logged as warnings and `Ok(())` is returned as they should
    /// not distrub the operation of `PeerManager`.
    ///
    /// If an error has ban score greater than zero, the peer score is updated and connection
    /// to that peer is possibly closed if their scored crossed the ban threshold.
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
                log::warn!("non-fatal error occurred: {}", err);

                if let Some(peer_id) = peer_id {
                    log::info!("adjust peer score for peer {}, reason {}", peer_id, err);
                    return self.adjust_peer_score(peer_id, err.ban_score()).await;
                }

                Ok(())
            }
        }
    }

    /// Run the `PeerManager` event loop
    ///
    /// The event loop has three main responsibilities:
    /// - listening to and handling control events from [`crate::sync::SyncManager`]/
    /// [`crate::pubsub::PubSubMessageHandler`]/RPC
    /// - listening to network events
    /// - updating internal state
    ///
    /// After handling an event from one of the aforementioned sources, the event loop
    /// handles the error (if any) and runs the [`PeerManager::heartbeat()`] function
    /// to perform swarm maintenance. If the `PeerManager` doesn't receive any events,
    /// [`PEER_MGR_HEARTBEAT_INTERVAL`] defines how often the heartbeat function is called.
    /// This is done to prevent the `PeerManager` from stalling in case the network doesn't
    /// have any events.
    pub async fn run(&mut self) -> crate::Result<void::Void> {
        loop {
            tokio::select! {
                event = self.rx_swarm.recv().fuse() => match event.ok_or(P2pError::ChannelClosed)? {
                    event::SwarmEvent::Connect(addr, response) => {
                        log::debug!(
                            "try to establish outbound connection to peer at address {:?}",
                            addr
                        );

                        let res = self.connect(addr.clone()).await.map(|_| {
                            self.pending.insert(addr.clone(), Some(response));
                        });
                        self.handle_result(None, res).await?;
                    }
                    event::SwarmEvent::Disconnect(peer_id, response) => {
                        log::debug!("disconnect peer {} from the swarm", peer_id);

                        response
                            .send(self.handle.disconnect(peer_id).await)
                            .map_err(|_| P2pError::ChannelClosed)?;
                    }
                    event::SwarmEvent::AdjustPeerScore(peer_id, score, response) => {
                        log::debug!("adjust peer {} score: {}", peer_id, score);

                        response
                            .send(self.adjust_peer_score(peer_id, score).await)
                            .map_err(|_| P2pError::ChannelClosed)?;
                    }
                    event::SwarmEvent::GetPeerCount(response) => {
                        response.send(self.peers.len()).map_err(|_| P2pError::ChannelClosed)?;
                    }
                    event::SwarmEvent::GetBindAddress(response) => {
                        let addr = self.handle.local_addr();
                        let addr = addr.await?.map_or("<unavailable>".to_string(), |addr| addr.to_string());
                        response.send(addr).map_err(|_| P2pError::ChannelClosed)?;
                    }
                    event::SwarmEvent::GetPeerId(response) => response
                        .send(self.handle.peer_id().to_string())
                        .map_err(|_| P2pError::ChannelClosed)?,
                    event::SwarmEvent::GetConnectedPeers(response) => {
                        let peers = self.peers.iter().map(|(id, _)| id.to_string()).collect::<Vec<_>>();
                        response.send(peers).map_err(|_| P2pError::ChannelClosed)?
                    }
                },
                event = self.handle.poll_next() => match event {
                    Ok(event) => match event {
                        net::types::ConnectivityEvent::IncomingConnection { peer_info, addr } => {
                            let peer_id = peer_info.peer_id;

                            match self.accept_inbound_connection(addr, peer_info).await {
                                Ok(_) => {},
                                Err(P2pError::ChannelClosed) => return Err(P2pError::ChannelClosed),
                                Err(P2pError::PeerError(err)) => {
                                    log::warn!("peer error for peer {}: {}", peer_id, err);
                                    self.handle.disconnect(peer_id).await?;
                                }
                                Err(P2pError::ProtocolError(err)) => {
                                    log::warn!("peer error for peer {}: {}", peer_id, err);
                                    self.adjust_peer_score(peer_id, err.ban_score()).await?;
                                }
                                Err(err) => {
                                    log::error!("unknown error for peer {}: {}", peer_id, err);
                                }
                            }
                        }
                        net::types::ConnectivityEvent::ConnectionAccepted { addr, peer_info } => {
                            let peer_id = peer_info.peer_id;
                            let res = self.accept_connection(peer_info).await;
                            self.handle_result(Some(peer_id), res).await?;

                            match self.pending.remove(&addr) {
                                Some(Some(channel)) => channel.send(Ok(())).map_err(|_| P2pError::ChannelClosed)?,
                                Some(None) => {},
                                None => log::error!("connection accepted but it's not pending?"),
                            }
                        }
                        net::types::ConnectivityEvent::ConnectionClosed { peer_id } => {
                            let res = self.close_connection(peer_id).await;
                            self.handle_result(Some(peer_id), res).await?;
                        }
                        net::types::ConnectivityEvent::ConnectionError { addr, error } => {
                            let res = self.handle_outbound_error(addr, error);
                            self.handle_result(None, res).await?;
                        }
                        net::types::ConnectivityEvent::Discovered { peers } => {
                            self.peer_discovered(&peers);
                        }
                        net::types::ConnectivityEvent::Expired { peers } => {
                            self.peer_expired(&peers);
                        }
                        net::types::ConnectivityEvent::Disconnected { .. } => {
                            // TODO: add tests
                        }
                        net::types::ConnectivityEvent::Misbehaved { peer_id, error } => {
                            let res = self.adjust_peer_score(peer_id, error.ban_score()).await;
                            self.handle_result(Some(peer_id), res).await?;
                        }
                        net::types::ConnectivityEvent::Error { .. } => {
                            // TODO:
                        }
                    }
                    Err(err) => {
                        log::error!("failed to read network event: {:?}", err);
                        self.handle_result(None, Err(err)).await?;
                    }
                },
                _event = tokio::time::sleep(PEER_MGR_HEARTBEAT_INTERVAL) => {}
            }

            // finally update peer manager state
            self.heartbeat().await?;
        }
    }
}

#[cfg(test)]
mod tests;
