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

pub mod global_ip;
pub mod peer_context;
pub mod peerdb;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use crypto::random::{make_pseudo_rng, seq::IteratorRandom, Rng};
use tokio::{sync::mpsc, time::Instant};

use chainstate::ban_score::BanScore;
use common::{chain::ChainConfig, primitives::semver::SemVer, time_getter::TimeGetter};
use logging::log;
use utils::ensure;

use crate::{
    config::P2pConfig,
    error::{P2pError, PeerError, ProtocolError},
    event::{PeerManagerEvent, SyncControlEvent},
    interface::types::ConnectedPeer,
    message::{
        AddrListRequest, AddrListResponse, AnnounceAddrRequest, PeerManagerMessage, PingRequest,
        PingResponse,
    },
    net::{
        self,
        default_backend::transport::TransportAddress,
        types::{ConnectivityEvent, Role},
        types::{PeerInfo, PubSubTopic},
        AsBannableAddress, ConnectivityService, NetworkingService,
    },
    types::{
        peer_address::{PeerAddress, PeerAddressIp4, PeerAddressIp6},
        peer_id::PeerId,
    },
    utils::oneshot_nofail,
};

use self::{
    peer_context::{PeerContext, SentPing},
    peerdb::storage::PeerDbStorage,
};

/// Maximum number of connections the [`PeerManager`] is allowed to have open
const MAX_ACTIVE_CONNECTIONS: usize = 128;

/// Maximum number of outbound connections the [`PeerManager`] is allowed to have open
const MAX_OUTBOUND_CONNECTIONS: usize = 8;

/// Lower bound for how often [`PeerManager::heartbeat()`] is called
const PEER_MGR_HEARTBEAT_INTERVAL_MIN: Duration = Duration::from_secs(5);
/// Upper bound for how often [`PeerManager::heartbeat()`] is called
const PEER_MGR_HEARTBEAT_INTERVAL_MAX: Duration = Duration::from_secs(30);

/// How many addresses are allowed to be sent
const MAX_ADDRESS_COUNT: usize = 1000;

/// To how many peers resend received address
const PEER_ADDRESS_RESEND_COUNT: usize = 2;

/// Hardcoded seed DNS hostnames
// TODO: Replace with actual values
const DNS_SEEDS: [&str; 2] = ["seed.mintlayer.org", "seed2.mintlayer.org"];
/// Maximum number of records accepted in a single DNS server response
const MAX_DNS_RECORDS: usize = 10;
/// Minimum time to query DNS servers
const MIN_DNS_QUERY_PERIOD: Duration = Duration::from_secs(60);

pub struct PeerManager<T, S>
where
    T: NetworkingService,
{
    /// Chain configuration.
    chain_config: Arc<ChainConfig>,

    /// P2P configuration.
    p2p_config: Arc<P2pConfig>,

    /// Handle for sending/receiving connectivity events
    peer_connectivity_handle: T::ConnectivityHandle,

    /// RX channel for receiving control events
    rx_peer_manager: mpsc::UnboundedReceiver<PeerManagerEvent<T>>,

    /// TX channel for sending events to SyncManager
    tx_sync: mpsc::UnboundedSender<SyncControlEvent>,

    /// Hashmap of pending outbound connections
    pending_connects: HashMap<T::Address, Option<oneshot_nofail::Sender<crate::Result<()>>>>,

    /// Hashmap of pending disconnect requests
    pending_disconnects: HashMap<PeerId, Option<oneshot_nofail::Sender<crate::Result<()>>>>,

    /// Set of active peers
    peers: BTreeMap<PeerId, PeerContext<T::Address>>,

    /// Peer database
    peerdb: peerdb::PeerDb<T, S>,

    /// Last time the DNS seed was loaded
    last_dns_reload: Option<Instant>,

    /// List of connected peers that subscribed to PeerAddresses topic
    subscribed_to_peer_addresses: BTreeSet<PeerId>,
}

impl<T, S> PeerManager<T, S>
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    S: PeerDbStorage,
{
    pub fn new(
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        handle: T::ConnectivityHandle,
        rx_peer_manager: mpsc::UnboundedReceiver<PeerManagerEvent<T>>,
        tx_sync: mpsc::UnboundedSender<SyncControlEvent>,
        time_getter: TimeGetter,
        peerdb_storage: S,
    ) -> crate::Result<Self> {
        let peerdb = peerdb::PeerDb::new(Arc::clone(&p2p_config), time_getter, peerdb_storage)?;
        utils::ensure!(
            !p2p_config.ping_timeout.is_zero(),
            P2pError::InvalidConfigurationValue("ping timeout can't be 0".into())
        );
        Ok(Self {
            peer_connectivity_handle: handle,
            rx_peer_manager,
            tx_sync,
            peerdb,
            peers: BTreeMap::new(),
            pending_connects: HashMap::new(),
            pending_disconnects: HashMap::new(),
            chain_config,
            p2p_config,
            last_dns_reload: None,
            subscribed_to_peer_addresses: BTreeSet::new(),
        })
    }

    /// Verify software version compatibility
    ///
    /// Make sure that local and remote peer have the same software version
    fn validate_version(&self, version: &SemVer) -> bool {
        // TODO: handle upgrades of versions
        version == self.chain_config.version()
    }

    fn is_peer_address_valid(&self, address: &PeerAddress) -> bool {
        <T::Address as TransportAddress>::from_peer_address(
            address,
            *self.p2p_config.allow_discover_private_ips,
        )
        .is_some()
    }

    /// Discover public addresses for this node after a new outbound connection is made
    ///
    /// *receiver_address* is this host socket address as seen and reported by remote peer.
    /// This should work for hosts with public IPs and for hosts behind NAT with port forwarding (same port is assumed).
    /// This won't work for majority of nodes but that should be accepted.
    fn handle_outbound_receiver_address(
        &mut self,
        peer_id: PeerId,
        receiver_address: PeerAddress,
    ) -> crate::Result<()> {
        if !self.subscribed_to_peer_addresses.contains(&peer_id) {
            return Ok(());
        }

        // Take IP and use port numbers from all listening sockets (with same IP version)
        let discovered_own_addresses = self
            .peer_connectivity_handle
            .local_addresses()
            .iter()
            .map(TransportAddress::as_peer_address)
            .filter_map(
                |listening_address| match (&receiver_address, listening_address) {
                    (PeerAddress::Ip4(receiver), PeerAddress::Ip4(listener)) => {
                        Some(PeerAddress::Ip4(PeerAddressIp4 {
                            ip: receiver.ip,
                            port: listener.port,
                        }))
                    }
                    (PeerAddress::Ip6(receiver), PeerAddress::Ip6(listener)) => {
                        Some(PeerAddress::Ip6(PeerAddressIp6 {
                            ip: receiver.ip,
                            port: listener.port,
                        }))
                    }
                    _ => None,
                },
            )
            .filter_map(|address| {
                TransportAddress::from_peer_address(
                    &address,
                    *self.p2p_config.allow_discover_private_ips,
                )
            })
            .collect::<Vec<_>>();

        for address in discovered_own_addresses {
            self.announce_address(peer_id, address)?;
        }

        Ok(())
    }

    /// Send address announcement to the selected peer (if the address is new)
    fn announce_address(&mut self, peer_id: PeerId, address: T::Address) -> crate::Result<()> {
        let peer = self.peers.get_mut(&peer_id).expect("peer must be known");
        if !peer.announced_addresses.contains(&address) {
            self.peer_connectivity_handle.send_message(
                peer_id,
                PeerManagerMessage::AnnounceAddrRequest(AnnounceAddrRequest {
                    address: address.as_peer_address(),
                }),
            )?;
            peer.announced_addresses.insert(address);
        }
        Ok(())
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
        info: PeerInfo,
        receiver_address: Option<PeerAddress>,
    ) -> crate::Result<()> {
        let peer_id = info.peer_id;

        ensure!(
            info.is_compatible(&self.chain_config),
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
            !self.is_peer_connected(info.peer_id),
            P2pError::PeerError(PeerError::PeerAlreadyExists),
        );
        ensure!(
            !self.peerdb.is_address_connected(&address),
            P2pError::PeerError(PeerError::PeerAlreadyExists),
        );

        if role == Role::Outbound {
            self.peer_connectivity_handle.send_message(
                peer_id,
                PeerManagerMessage::AddrListRequest(AddrListRequest {}),
            )?;
        }

        log::info!(
            "peer connected, peer_id: {}, address: {address:?}, {:?}",
            info.peer_id,
            role
        );

        if info.subscriptions.contains(&PubSubTopic::PeerAddresses) {
            self.subscribed_to_peer_addresses.insert(peer_id);
        }

        let old_value = self.peers.insert(
            info.peer_id,
            PeerContext {
                info,
                address: address.clone(),
                role,
                score: 0,
                sent_ping: None,
                announced_addresses: HashSet::new(),
            },
        );
        assert!(old_value.is_none());

        self.peerdb.peer_connected(address, role);

        if let (Some(receiver_address), Role::Outbound) = (receiver_address, role) {
            self.handle_outbound_receiver_address(peer_id, receiver_address)?;
        }

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
        info: net::types::PeerInfo,
        receiver_address: Option<PeerAddress>,
    ) -> crate::Result<()> {
        log::debug!("validate inbound connection, inbound address {address:?}");

        ensure!(
            !self.is_peer_connected(info.peer_id),
            P2pError::PeerError(PeerError::PeerAlreadyExists),
        );

        let bannable_address = address.as_bannable();
        ensure!(
            !self.peerdb.is_address_banned(&bannable_address),
            P2pError::PeerError(PeerError::BannedAddress(address.to_string())),
        );

        // If the maximum number of connections is reached, the connection cannot be
        // accepted even if it's valid.
        if self.active_peer_count() >= MAX_ACTIVE_CONNECTIONS {
            return Err(P2pError::PeerError(PeerError::TooManyPeers));
        }

        self.accept_connection(address, Role::Inbound, info, receiver_address)
    }

    /// The connection to a remote peer is reported as closed.
    ///
    /// This can happen when the remote peer has dropped its connection
    /// or if a disconnect request has been sent by PeerManager to the backend.
    fn connection_closed(&mut self, peer_id: PeerId) -> crate::Result<()> {
        // The peer will not be in `peers` for rejected inbound connections
        if let Some(peer) = self.peers.remove(&peer_id) {
            log::info!(
                "peer disconnected, peer_id: {}, address: {:?}",
                peer.info.peer_id,
                peer.address
            );

            self.tx_sync.send(SyncControlEvent::Disconnected(peer_id))?;

            if let Some(Some(response)) = self.pending_disconnects.remove(&peer_id) {
                response.send(Ok(()));
            }

            self.subscribed_to_peer_addresses.remove(&peer_id);

            self.peerdb.peer_disconnected(peer.address, peer.role);
        }

        Ok(())
    }

    /// Adjust peer score
    ///
    /// If the peer is known, update its existing peer score and report
    /// if it should be disconnected when score reached the threshold.
    /// Unknown peers are reported as to be disconnected.
    ///
    /// If peer is banned, it is removed from the connected peers
    /// and its address is marked as banned.
    fn adjust_peer_score(&mut self, peer_id: PeerId, score: u32) -> crate::Result<()> {
        let peer = match self.peers.get_mut(&peer_id) {
            Some(peer) => peer,
            None => return Ok(()),
        };

        peer.score = peer.score.saturating_add(score);
        log::info!(
            "Adjusting peer score for peer {peer_id}, adjustment {score}, new score {}",
            peer.score
        );

        if peer.score >= *self.p2p_config.ban_threshold {
            self.peerdb.ban_peer(&peer.address);
            self.disconnect(peer_id, None)?;
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
        if let Some(Some(channel)) = self.pending_connects.remove(&address) {
            channel.send(Err(error));
        }

        self.peerdb.report_outbound_failure(address);
        Ok(())
    }

    /// Attempt to establish an outbound connection
    ///
    /// This function doesn't block on the call but sends a command to the
    /// networking backend which then reports at some point in the future
    /// whether the connection failed or succeeded.
    fn try_connect(&mut self, address: T::Address) -> crate::Result<()> {
        ensure!(
            !self.pending_connects.contains_key(&address),
            P2pError::PeerError(PeerError::Pending(address.to_string())),
        );

        ensure!(
            !self.peerdb.is_address_connected(&address),
            P2pError::PeerError(PeerError::PeerAlreadyExists),
        );

        let bannable_address = address.as_bannable();
        ensure!(
            !self.peerdb.is_address_banned(&bannable_address),
            P2pError::PeerError(PeerError::BannedAddress(address.to_string())),
        );

        self.peer_connectivity_handle.connect(address)
    }

    /// Establish an outbound connection
    fn connect(
        &mut self,
        address: T::Address,
        response: Option<oneshot_nofail::Sender<crate::Result<()>>>,
    ) -> crate::Result<()> {
        log::debug!("try to establish outbound connection to peer at address {address:?}");

        let res = self.try_connect(address.clone());

        match res {
            Ok(()) => {
                self.pending_connects.insert(address.clone(), response);
                self.peerdb.outbound_connection_initiated(address);
            }
            Err(e) => {
                if let Some(response) = response {
                    response.send(Err(e));
                }
            }
        }

        Ok(())
    }

    fn try_disconnect(&mut self, peer_id: PeerId) -> crate::Result<()> {
        ensure!(
            !self.pending_disconnects.contains_key(&peer_id),
            P2pError::PeerError(PeerError::Pending(peer_id.to_string())),
        );

        ensure!(
            self.peers.contains_key(&peer_id),
            P2pError::PeerError(PeerError::PeerDisconnected),
        );

        self.peer_connectivity_handle.disconnect(peer_id)
    }

    /// Disconnect an existing connection (inbound or outbound)
    ///
    /// The decision to close the connection is made either by the user via RPC
    /// or by the [`PeerManager::heartbeat()`] function which has decided to cull
    /// this connection in favor of another potential connection.
    fn disconnect(
        &mut self,
        peer_id: PeerId,
        response: Option<oneshot_nofail::Sender<crate::Result<()>>>,
    ) -> crate::Result<()> {
        log::debug!("disconnect peer {peer_id}");

        let res = self.try_disconnect(peer_id);

        match res {
            Ok(()) => {
                self.pending_disconnects.insert(peer_id, response);
            }
            Err(e) => {
                if let Some(response) = response {
                    response.send(Err(e));
                }
            }
        }

        Ok(())
    }

    /// Fill PeerDb with addresses from DNS seed servers
    async fn reload_dns_seed(&mut self) {
        let now = Instant::now();
        let resolved_recently = self
            .last_dns_reload
            .map(|time| now.duration_since(time) < MIN_DNS_QUERY_PERIOD)
            .unwrap_or(false);
        if resolved_recently {
            return;
        }
        self.last_dns_reload = Some(now);

        log::debug!("Resolve DNS seed...");
        let results = futures::future::join_all(
            DNS_SEEDS
                .iter()
                .map(|host| tokio::net::lookup_host((*host, self.chain_config.p2p_port()))),
        )
        .await;

        let mut total = 0;
        for result in results {
            match result {
                Ok(list) => {
                    list.filter_map(|addr| {
                        TransportAddress::from_peer_address(
                            &addr.into(),
                            *self.p2p_config.allow_discover_private_ips,
                        )
                    })
                    // Randomize selection because records can be sorted by type (A and AAAA)
                    .choose_multiple(&mut make_pseudo_rng(), MAX_DNS_RECORDS)
                    .into_iter()
                    .for_each(|addr| {
                        total += 1;
                        self.peerdb.peer_discovered(&addr);
                    });
                }
                Err(err) => {
                    log::error!("resolve DNS seed failed: {err}");
                }
            }
        }
        log::debug!("DNS seed records found: {total}");
    }

    /// Maintains the peer manager state.
    ///
    /// `PeerManager::heartbeat()` is called every time a network/control event is received
    /// or the heartbeat timer of the event loop expires. In other words, the peer manager state
    /// is checked and updated at least once every 30 seconds. In high-traffic scenarios the
    /// update interval is clamped to a sensible lower bound. `PeerManager` will keep track of
    /// when it last update its own state and if the time since last update is less than the
    /// configured lower bound, *heartbeat* won't be called.
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
        let new_addresses = self.peerdb.select_new_outbound_addresses();

        // Try to get some records from DNS servers if there are no addresses to connect.
        // Do this only if no peers are currently connected.
        let new_addresses = if new_addresses.is_empty()
            && self.peers.is_empty()
            && self.pending_connects.is_empty()
        {
            self.reload_dns_seed().await;
            self.peerdb.select_new_outbound_addresses()
        } else {
            new_addresses
        };

        for address in new_addresses {
            self.connect(address, None)?;
        }

        Ok(())
    }

    fn handle_incoming_message(
        &mut self,
        peer: PeerId,
        message: PeerManagerMessage,
    ) -> crate::Result<()> {
        match message {
            PeerManagerMessage::AddrListRequest(_) => self.handle_add_list_request(peer),
            PeerManagerMessage::AnnounceAddrRequest(r) => {
                self.handle_announce_addr_request(peer, r.address)
            }
            PeerManagerMessage::PingRequest(r) => self.handle_ping_request(peer, r.nonce),
            PeerManagerMessage::AddrListResponse(r) => self.handle_add_list_response(r.addresses),
            PeerManagerMessage::PingResponse(r) => self.handle_ping_response(peer, r.nonce),
        }
    }

    fn handle_add_list_request(&mut self, peer: PeerId) -> crate::Result<()> {
        let addresses = self
            .peerdb
            .known_addresses()
            .map(TransportAddress::as_peer_address)
            .filter(|address| self.is_peer_address_valid(address))
            .choose_multiple(&mut make_pseudo_rng(), MAX_ADDRESS_COUNT);

        self.peer_connectivity_handle.send_message(
            peer,
            PeerManagerMessage::AddrListResponse(AddrListResponse { addresses }),
        )
    }

    fn handle_announce_addr_request(
        &mut self,
        peer: PeerId,
        address: PeerAddress,
    ) -> crate::Result<()> {
        // TODO: Rate limit announce address requests to prevent DoS attacks.
        // For example it's 0.1 req/sec in Bitcoin Core.
        if let Some(address) = TransportAddress::from_peer_address(
            &address,
            *self.p2p_config.allow_discover_private_ips,
        ) {
            self.peerdb.peer_discovered(&address);

            self.peers
                .get_mut(&peer)
                .expect("peer sending AnnounceAddrRequest must be known")
                .announced_addresses
                .insert(address.clone());

            let peer_ids = self
                .subscribed_to_peer_addresses
                .iter()
                .cloned()
                .choose_multiple(&mut make_pseudo_rng(), PEER_ADDRESS_RESEND_COUNT);
            for new_peer_id in peer_ids {
                self.announce_address(new_peer_id, address.clone())?;
            }
        }
        Ok(())
    }

    fn handle_ping_request(&mut self, peer: PeerId, nonce: u64) -> crate::Result<()> {
        self.peer_connectivity_handle.send_message(
            peer,
            PeerManagerMessage::PingResponse(PingResponse { nonce }),
        )
    }

    fn handle_add_list_response(&mut self, addresses: Vec<PeerAddress>) -> crate::Result<()> {
        // TODO: Ban the peer if the response is unexpected or invalid (more than 1000 addresses)
        for address in addresses {
            if let Some(address) = TransportAddress::from_peer_address(
                &address,
                *self.p2p_config.allow_discover_private_ips,
            ) {
                self.peerdb.peer_discovered(&address);
            }
        }
        Ok(())
    }

    fn handle_ping_response(&mut self, peer: PeerId, nonce: u64) -> crate::Result<()> {
        if let Some(peer) = self.peers.get_mut(&peer) {
            if peer.sent_ping.as_ref().map(|sent_ping| sent_ping.nonce) == Some(nonce) {
                // Correct reply received, clear pending request
                peer.sent_ping = None;
            }
        }
        Ok(())
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
    pub fn handle_result(
        &mut self,
        peer_id: Option<PeerId>,
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
                    return self.adjust_peer_score(peer_id, err.ban_score());
                }

                Ok(())
            }
        }
    }

    /// Handle control event.
    ///
    /// Handle events from an outside controller (rpc, for example) that sets/gets values for PeerManager.
    fn handle_control_event(&mut self, event: PeerManagerEvent<T>) -> crate::Result<()> {
        match event {
            PeerManagerEvent::Connect(address, response) => {
                self.connect(address, Some(response))?;
            }
            PeerManagerEvent::Disconnect(peer_id, response) => {
                self.disconnect(peer_id, Some(response))?;
            }
            PeerManagerEvent::AdjustPeerScore(peer_id, score, response) => {
                log::debug!("adjust peer {peer_id} score: {score}");

                response.send(self.adjust_peer_score(peer_id, score));
            }
            PeerManagerEvent::GetPeerCount(response) => {
                response.send(self.active_peer_count());
            }
            PeerManagerEvent::GetBindAddresses(response) => {
                let addr = self
                    .peer_connectivity_handle
                    .local_addresses()
                    .iter()
                    .map(|addr| addr.to_string())
                    .collect();
                response.send(addr);
            }
            PeerManagerEvent::GetConnectedPeers(response) => {
                let peers = self.get_connected_peers();
                response.send(peers);
            }
        }

        Ok(())
    }

    /// Handle connectivity event
    fn handle_connectivity_event_result(
        &mut self,
        event_res: crate::Result<ConnectivityEvent<T::Address>>,
    ) -> crate::Result<()> {
        match event_res {
            Ok(event) => match event {
                ConnectivityEvent::Message { peer, message } => {
                    self.handle_incoming_message(peer, message)?
                }
                ConnectivityEvent::InboundAccepted {
                    address,
                    peer_info,
                    receiver_address,
                } => {
                    let peer_id = peer_info.peer_id;

                    match self.accept_inbound_connection(address, peer_info, receiver_address) {
                        Ok(_) => {}
                        Err(P2pError::ChannelClosed) => return Err(P2pError::ChannelClosed),
                        Err(P2pError::PeerError(err)) => {
                            log::warn!("peer error for peer {peer_id}: {err}");
                            self.peer_connectivity_handle.disconnect(peer_id)?;
                        }
                        Err(P2pError::ProtocolError(err)) => {
                            log::warn!("peer error for peer {peer_id}: {err}");
                            self.adjust_peer_score(peer_id, err.ban_score())?;
                        }
                        Err(err) => {
                            log::error!("unknown error for peer {peer_id}: {err}");
                        }
                    }
                }
                ConnectivityEvent::OutboundAccepted {
                    address,
                    peer_info,
                    receiver_address,
                } => {
                    let peer_id = peer_info.peer_id;
                    let res = self.accept_connection(
                        address.clone(),
                        Role::Outbound,
                        peer_info,
                        receiver_address,
                    );
                    self.handle_result(Some(peer_id), res)?;

                    match self.pending_connects.remove(&address) {
                        Some(Some(channel)) => {
                            channel.send(Ok(()));
                        }
                        Some(None) => {}
                        None => log::error!("connection accepted but it's not pending?"),
                    }
                }
                ConnectivityEvent::ConnectionClosed { peer_id } => {
                    let res = self.connection_closed(peer_id);
                    self.handle_result(Some(peer_id), res)?;
                }
                ConnectivityEvent::ConnectionError { address, error } => {
                    let res = self.handle_outbound_error(address, error);
                    self.handle_result(None, res)?;
                }
                ConnectivityEvent::Misbehaved { peer_id, error } => {
                    let res = self.adjust_peer_score(peer_id, error.ban_score());
                    self.handle_result(Some(peer_id), res)?;
                }
            },
            Err(err) => {
                log::error!("failed to read network event: {err:?}");
                self.handle_result(None, Err(err))?;
            }
        }

        Ok(())
    }

    /// Get the number of active peers
    pub fn active_peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Returns short info about all connected peers
    pub fn get_connected_peers(&self) -> Vec<ConnectedPeer> {
        self.peers.values().map(Into::into).collect()
    }

    /// Checks if the peer is in active state
    pub fn is_peer_connected(&self, peer_id: PeerId) -> bool {
        self.peers.get(&peer_id).is_some()
    }

    /// Sends ping requests and disconnects peers that do not respond in time
    fn ping_check(&mut self) -> crate::Result<()> {
        let now = Instant::now();
        let mut dead_peers = Vec::new();
        for (peer_id, peer) in self.peers.iter_mut() {
            // If a ping has already been sent, wait for a reply first, do not send another ping request!
            match &peer.sent_ping {
                Some(sent_ping) => {
                    if now.duration_since(sent_ping.timestamp) >= *self.p2p_config.ping_timeout {
                        log::info!("ping check: dead peer detected: {peer_id}");
                        dead_peers.push(*peer_id);
                    } else {
                        log::debug!("ping check: slow peer detected: {peer_id}");
                    }
                }
                None => {
                    let nonce = make_pseudo_rng().gen();
                    self.peer_connectivity_handle.send_message(
                        *peer_id,
                        PeerManagerMessage::PingRequest(PingRequest { nonce }),
                    )?;
                    peer.sent_ping = Some(SentPing {
                        nonce,
                        timestamp: now,
                    });
                }
            }
        }

        for peer_id in dead_peers {
            self.disconnect(peer_id, None)?;
        }

        Ok(())
    }

    /// Runs the `PeerManager` event loop.
    ///
    /// The event loop has this main responsibilities:
    /// - listening to and handling control events from [`crate::sync::BlockSyncManager`]/RPC
    /// - listening to network events
    /// - updating internal state
    /// - sending and checking ping requests
    ///
    /// After handling an event from one of the aforementioned sources, the event loop
    /// handles the error (if any) and runs the [`PeerManager::heartbeat()`] function
    /// to perform the peer manager maintenance. If the `PeerManager` doesn't receive any events,
    /// [`PEER_MGR_HEARTBEAT_INTERVAL_MIN`] and [`PEER_MGR_HEARTBEAT_INTERVAL_MAX`] defines how
    /// often the heartbeat function is called.
    /// This is done to prevent the `PeerManager` from stalling in case the network doesn't
    /// have any events.
    pub async fn run(&mut self) -> crate::Result<void::Void> {
        let ping_check_enabled = !self.p2p_config.ping_check_period.is_zero();
        let mut ping_check_interval = if ping_check_enabled {
            tokio::time::interval(*self.p2p_config.ping_check_period)
        } else {
            // Use any valid (non-zero) value
            tokio::time::interval(Duration::MAX)
        };

        // Last time when heartbeat was called
        let mut last_heartbeat = None;

        loop {
            // Run heartbeat if needed
            let now = Instant::now();
            let recent_heartbeat = last_heartbeat
                .map(|time| now.duration_since(time) < PEER_MGR_HEARTBEAT_INTERVAL_MIN)
                .unwrap_or(false);
            if !recent_heartbeat {
                self.heartbeat().await?;
                last_heartbeat = Some(now);
            }

            tokio::select! {
                event = self.rx_peer_manager.recv() => {
                    self.handle_control_event(event.ok_or(P2pError::ChannelClosed)?)?;
                },
                event_res = self.peer_connectivity_handle.poll_next() => {
                    self.handle_connectivity_event_result(event_res)?;
                },
                _event = ping_check_interval.tick(), if ping_check_enabled => {
                    self.ping_check()?;
                }
                _event = tokio::time::sleep(PEER_MGR_HEARTBEAT_INTERVAL_MAX) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests;
