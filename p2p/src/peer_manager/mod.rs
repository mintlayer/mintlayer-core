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

mod addr_list_response_cache;
pub mod address_groups;
pub mod config;
pub mod dns_seed;
pub mod peer_context;
pub mod peerdb;
pub mod peerdb_common;
pub mod peers_eviction;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
    sync::Arc,
    time::Duration,
};

use futures::never::Never;
use tokio::sync::mpsc;

use chainstate::ban_score::BanScore;
use common::{
    chain::ChainConfig,
    primitives::time::{duration_to_int, Time},
    time_getter::TimeGetter,
};
use logging::log;
use networking::types::ConnectionDirection;
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress, IsGlobalIp};
use randomness::{make_pseudo_rng, seq::IteratorRandom, Rng};
use utils::{bloom_filters::rolling_bloom_filter::RollingBloomFilter, ensure, set_flag::SetFlag};
use utils_networking::IpOrSocketAddress;

use crate::{
    config::P2pConfig,
    disconnection_reason::DisconnectionReason,
    error::{ConnectionValidationError, P2pError, PeerError, ProtocolError},
    interface::types::ConnectedPeer,
    message::{
        AddrListRequest, AddrListResponse, AnnounceAddrRequest, PeerManagerMessage, PingRequest,
        PingResponse, WillDisconnectMessage,
    },
    net::{
        types::{
            services::{Service, Services},
            ConnectivityEvent, PeerInfo, PeerRole,
        },
        ConnectivityService, NetworkingService,
    },
    peer_manager_event::PeerDisconnectionDbAction,
    sync::sync_status::PeerBlockSyncStatus,
    types::{
        peer_address::{PeerAddress, PeerAddressIp4, PeerAddressIp6},
        peer_id::PeerId,
    },
    utils::{oneshot_nofail, rate_limiter::RateLimiter},
    PeerManagerEvent,
};

use self::{
    addr_list_response_cache::AddrListResponseCache,
    address_groups::AddressGroup,
    dns_seed::{DefaultDnsSeed, DnsSeed},
    peer_context::{PeerContext, SentPing},
    peerdb::storage::PeerDbStorage,
};

/// Lower bound for how often [`PeerManager::heartbeat()`] is called
pub const HEARTBEAT_INTERVAL_MIN: Duration = Duration::from_secs(5);
/// Upper bound for how often [`PeerManager::heartbeat()`] is called
pub const HEARTBEAT_INTERVAL_MAX: Duration = Duration::from_secs(30);

/// How often resend own address to a specific peer (on average)
const RESEND_OWN_ADDRESS_TO_PEER_PERIOD: Duration = Duration::from_secs(24 * 60 * 60);

/// The minimal interval at which to query DNS seed servers.
pub const DNS_SEED_QUERY_INTERVAL: Duration = Duration::from_secs(60);

/// The maximum rate of address announcements the node will process from a peer (value as in Bitcoin Core).
pub const MAX_ADDR_RATE_PER_SECOND: f64 = 0.1;
/// Bucket size used to rate limit address announcements from a peer.
/// Use 1 to allow peers to send one own address immediately after connecting.
pub const ADDR_RATE_INITIAL_SIZE: u32 = 1;
/// Bucket size used to rate limit address announcements from a peer.
pub const ADDR_RATE_BUCKET_SIZE: u32 = 10;

/// To how many peers resend received address
const PEER_ADDRESS_RESEND_COUNT: usize = 2;

// Use the same parameters as Bitcoin Core (last 5000 addresses)
const PEER_ADDRESSES_ROLLING_BLOOM_FILTER_SIZE: usize = 5000;
const PEER_ADDRESSES_ROLLING_BLOOM_FPP: f64 = 0.001;

enum OutboundConnectType {
    Automatic {
        block_relay_only: bool,
    },
    Reserved,
    Manual {
        response_sender: oneshot_nofail::Sender<crate::Result<()>>,
    },
    Feeler,
}

impl OutboundConnectType {
    fn block_relay_only(&self) -> bool {
        match self {
            OutboundConnectType::Automatic { block_relay_only } => *block_relay_only,
            OutboundConnectType::Reserved
            | OutboundConnectType::Manual { response_sender: _ }
            | OutboundConnectType::Feeler => false,
        }
    }
}

impl From<&OutboundConnectType> for PeerRole {
    fn from(value: &OutboundConnectType) -> Self {
        match value {
            OutboundConnectType::Automatic { block_relay_only } => {
                if *block_relay_only {
                    PeerRole::OutboundBlockRelay
                } else {
                    PeerRole::OutboundFullRelay
                }
            }
            OutboundConnectType::Reserved => PeerRole::OutboundReserved,
            OutboundConnectType::Manual { response_sender: _ } => PeerRole::OutboundManual,
            OutboundConnectType::Feeler => PeerRole::Feeler,
        }
    }
}

struct PendingConnect {
    outbound_connect_type: OutboundConnectType,
}

struct PendingDisconnect {
    peerdb_action: PeerDisconnectionDbAction,
    response_sender: Option<oneshot_nofail::Sender<crate::Result<()>>>,
}

pub struct PeerManager<T, S>
where
    T: NetworkingService,
{
    /// Whether networking is enabled.
    networking_enabled: bool,

    /// Chain configuration.
    chain_config: Arc<ChainConfig>,

    /// P2P configuration.
    p2p_config: Arc<P2pConfig>,

    time_getter: TimeGetter,

    /// Handle for sending/receiving connectivity events
    peer_connectivity_handle: T::ConnectivityHandle,

    /// Channel receiver for receiving control events
    peer_mgr_event_receiver: mpsc::UnboundedReceiver<PeerManagerEvent>,

    /// Hashmap of pending outbound connections
    pending_outbound_connects: HashMap<SocketAddress, PendingConnect>,

    /// Hashmap of pending disconnect requests
    pending_disconnects: HashMap<PeerId, PendingDisconnect>,

    /// Map of all connected peers
    peers: BTreeMap<PeerId, PeerContext>,

    /// Peer database
    peerdb: peerdb::PeerDb<S>,

    /// List of connected peers that subscribed to PeerAddresses topic
    subscribed_to_peer_addresses: BTreeSet<PeerId>,

    peer_eviction_random_state: peers_eviction::RandomState,

    /// Cached address list responses.
    addr_list_response_cache: AddrListResponseCache,

    /// PeerManager's observer for use by tests.
    observer: Option<Box<dyn Observer + Send>>,

    /// Normally, this will be DefaultDnsSeed, which performs the actual address lookup, but tests can
    /// substitute it with a mock implementation.
    dns_seed: Box<dyn DnsSeed>,

    /// The time when PeerManager was initialized.
    init_time: Time,
    /// Last time when a new tip was added to the chainstate.
    last_chainstate_tip_block_time: Option<Time>,
    /// Last heartbeat time.
    last_heartbeat_time: Option<Time>,
    /// Last time dns seed was queried.
    last_dns_query_time: Option<Time>,
    /// Last time ping check was performed.
    last_ping_check_time: Option<Time>,
    /// The time after which a new feeler connection can be established.
    next_feeler_connection_time: Time,
}

/// Takes IP or socket address and converts it to socket address (adding the default peer port if IP address is used)
pub fn ip_or_socket_address_to_peer_address(
    address: &IpOrSocketAddress,
    chain_config: &ChainConfig,
) -> SocketAddress {
    SocketAddress::new(address.to_socket_address(chain_config.p2p_port()))
}

impl<T, S> PeerManager<T, S>
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    S: PeerDbStorage,
{
    pub fn new(
        networking_enabled: bool,
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        handle: T::ConnectivityHandle,
        peer_mgr_event_receiver: mpsc::UnboundedReceiver<PeerManagerEvent>,
        time_getter: TimeGetter,
        peerdb_storage: S,
    ) -> crate::Result<Self> {
        Self::new_generic(
            networking_enabled,
            chain_config.clone(),
            p2p_config.clone(),
            handle,
            peer_mgr_event_receiver,
            time_getter,
            peerdb_storage,
            None,
            Box::new(DefaultDnsSeed::new(chain_config, p2p_config)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_generic(
        networking_enabled: bool,
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        handle: T::ConnectivityHandle,
        peer_mgr_event_receiver: mpsc::UnboundedReceiver<PeerManagerEvent>,
        time_getter: TimeGetter,
        peerdb_storage: S,
        observer: Option<Box<dyn Observer + Send>>,
        dns_seed: Box<dyn DnsSeed + Send>,
    ) -> crate::Result<Self> {
        let mut rng = make_pseudo_rng();
        let peerdb = peerdb::PeerDb::new(
            &chain_config,
            Arc::clone(&p2p_config),
            time_getter.clone(),
            peerdb_storage,
        )?;
        let salt = peerdb.salt();
        let now = time_getter.get_time();
        let next_feeler_connection_time =
            Self::choose_next_feeler_connection_time(&p2p_config, now);
        assert!(!p2p_config.outbound_connection_timeout.is_zero());
        assert!(!p2p_config.ping_timeout.is_zero());

        Ok(PeerManager {
            networking_enabled,
            chain_config,
            p2p_config,
            time_getter,
            peer_connectivity_handle: handle,
            peer_mgr_event_receiver,
            pending_outbound_connects: HashMap::new(),
            pending_disconnects: HashMap::new(),
            peers: BTreeMap::new(),
            peerdb,
            subscribed_to_peer_addresses: BTreeSet::new(),
            peer_eviction_random_state: peers_eviction::RandomState::new(&mut rng),
            addr_list_response_cache: AddrListResponseCache::new(salt),
            observer,
            dns_seed,
            init_time: now,
            last_chainstate_tip_block_time: None,
            last_heartbeat_time: None,
            last_dns_query_time: None,
            last_ping_check_time: None,
            next_feeler_connection_time,
        })
    }

    fn choose_next_feeler_connection_time(p2p_config: &P2pConfig, now: Time) -> Time {
        let delay = p2p_config
            .peer_manager_config
            .feeler_connections_interval
            .mul_f64(utils::exp_rand::exponential_rand(&mut make_pseudo_rng()));
        (now + delay).expect("Unexpected time overflow")
    }

    /// Determine whether the address can be sent to peers via AddrListResponse.
    fn is_peer_address_discoverable(address: &PeerAddress, p2p_config: &P2pConfig) -> bool {
        address
            .as_discoverable_socket_address(*p2p_config.allow_discover_private_ips)
            .is_some()
    }

    /// Discover public addresses for this node after a new outbound connection is made
    ///
    /// `node_address_as_seen_by_peer` is this host socket address as seen and reported by remote peer.
    /// This should work for hosts with public IPs and for hosts behind NAT with port forwarding (same port is assumed).
    /// This won't work for majority of nodes but that should be accepted.
    fn discover_own_address(
        &mut self,
        peer_id: PeerId,
        peer_role: PeerRole,
        common_services: Services,
        node_address_as_seen_by_peer: Option<PeerAddress>,
    ) -> Option<SocketAddress> {
        let discover = match peer_role {
            PeerRole::Inbound | PeerRole::OutboundBlockRelay | PeerRole::Feeler => false,
            PeerRole::OutboundFullRelay | PeerRole::OutboundReserved | PeerRole::OutboundManual => {
                common_services.has_service(Service::PeerAddresses)
            }
        };
        if !discover {
            return None;
        }

        let node_address_as_seen_by_peer = node_address_as_seen_by_peer?;

        // Take IP and use port numbers from all listening sockets (with same IP version)
        let discovered_own_addresses = self
            .peer_connectivity_handle
            .local_addresses()
            .iter()
            .map(SocketAddress::as_peer_address)
            .filter_map(|listening_address| {
                match (&node_address_as_seen_by_peer, listening_address) {
                    (PeerAddress::Ip4(seen_by_peer), PeerAddress::Ip4(listening)) => {
                        Some(PeerAddress::Ip4(PeerAddressIp4 {
                            ip: seen_by_peer.ip,
                            port: listening.port,
                        }))
                    }
                    (PeerAddress::Ip6(seen_by_peer), PeerAddress::Ip6(listening)) => {
                        Some(PeerAddress::Ip6(PeerAddressIp6 {
                            ip: seen_by_peer.ip,
                            port: listening.port,
                        }))
                    }
                    _ => None,
                }
            })
            .filter_map(|address| {
                address.as_discoverable_socket_address(*self.p2p_config.allow_discover_private_ips)
            })
            .collect::<Vec<_>>();

        // Send only one address because of the rate limiter (see `ADDR_RATE_INITIAL_SIZE`).
        // Select a random address to give all addresses a chance to be discovered by the network.
        let chosen_discovered_address =
            discovered_own_addresses.iter().choose(&mut make_pseudo_rng()).cloned();

        log::debug!(
            "Own addresses discovered for peer {peer_id}: {:?}, chosen address: {:?}",
            discovered_own_addresses,
            chosen_discovered_address
        );

        chosen_discovered_address
    }

    /// Send address announcement to the selected peer (if the address is new)
    /// `peer_id` must be from the connected peer.
    fn announce_address(&mut self, peer_id: PeerId, address: SocketAddress) {
        let peer = self.peers.get_mut(&peer_id).expect("peer must be known");
        if !peer.announced_addresses.contains(&address) {
            log::debug!("Announcing address {address} to peer {peer_id}");

            Self::send_peer_message(
                &mut self.peer_connectivity_handle,
                peer_id,
                PeerManagerMessage::AnnounceAddrRequest(AnnounceAddrRequest {
                    address: address.as_peer_address(),
                }),
            );
            peer.announced_addresses.insert(&address, &mut make_pseudo_rng());
        }
    }

    fn send_own_address_to_peer(
        peer_connectivity_handle: &mut T::ConnectivityHandle,
        peer: &PeerContext,
    ) {
        if let Some(discovered_addr) = peer.discovered_own_address.as_ref() {
            log::debug!(
                "Sending own address {discovered_addr} to peer {}",
                peer.info.peer_id
            );

            Self::send_peer_message(
                peer_connectivity_handle,
                peer.info.peer_id,
                PeerManagerMessage::AnnounceAddrRequest(AnnounceAddrRequest {
                    address: discovered_addr.as_peer_address(),
                }),
            );
        }
    }

    fn resend_own_address_randomly(&mut self) {
        if let Some(peer) = self
            .peers
            .values_mut()
            .filter(|peer| peer.discovered_own_address.is_some())
            .choose(&mut make_pseudo_rng())
        {
            Self::send_own_address_to_peer(&mut self.peer_connectivity_handle, peer);
        }
    }

    fn is_whitelisted_node(&self, peer_role: PeerRole, address: &SocketAddress) -> bool {
        match peer_role {
            PeerRole::Inbound
            | PeerRole::OutboundFullRelay
            | PeerRole::OutboundBlockRelay
            | PeerRole::Feeler => {
                self.p2p_config.whitelisted_addresses.contains(&address.ip_addr())
            }
            PeerRole::OutboundReserved | PeerRole::OutboundManual => true,
        }
    }

    /// Adjust peer score
    ///
    /// Discourage the peer if the score reaches the corresponding threshold.
    fn adjust_peer_score(
        &mut self,
        peer_id: PeerId,
        score: u32,
        reason: &(impl std::fmt::Display + ?Sized),
    ) {
        let peer = match self.peers.get(&peer_id) {
            Some(peer) => peer,
            None => return,
        };

        if self.is_whitelisted_node(peer.peer_role, &peer.peer_address) {
            log::info!(
                "[peer id = {}] Ignoring peer score adjustment because the peer is whitelisted (adjustment: {}, reason: {})",
                peer_id,
                score,
                reason
            );
            return;
        }

        let peer = match self.peers.get_mut(&peer_id) {
            Some(peer) => peer,
            None => return,
        };

        peer.score = peer.score.saturating_add(score);

        log::info!(
            "[peer id = {}] Adjusting peer score by {}, new score: {}, reason: {}",
            peer_id,
            score,
            peer.score,
            reason
        );

        if let Some(o) = self.observer.as_mut() {
            o.on_peer_ban_score_adjustment(peer.peer_address, peer.score)
        }

        if peer.score >= *self.p2p_config.ban_config.discouragement_threshold {
            let address = peer.peer_address.as_bannable();
            self.discourage(address);
        }
    }

    /// Adjust peer score after a failed handshake.
    ///
    /// Note that currently intermediate scores are not stored in the peer db, so this call will
    /// only make any effect if the passed score is bigger than the threshold.
    fn adjust_peer_score_on_failed_handshake(
        &mut self,
        peer_address: SocketAddress,
        score: u32,
        reason: &(impl std::fmt::Display + ?Sized),
    ) {
        let whitelisted_node =
            self.pending_outbound_connects
                .get(&peer_address)
                .is_some_and(|pending_connect| {
                    self.is_whitelisted_node(
                        (&pending_connect.outbound_connect_type).into(),
                        &peer_address,
                    )
                });
        if whitelisted_node {
            log::info!(
                concat!(
                    "Ignoring peer score adjustment on failed handshake for peer at address {} ",
                    "because the peer is whitelisted (adjustment: {}, reason: {})"
                ),
                peer_address,
                score,
                reason,
            );
            return;
        }

        log::info!(
            "Adjusting peer score of a peer at address {} by {} on failed handshake, reason: {}",
            peer_address,
            score,
            reason
        );

        if let Some(o) = self.observer.as_mut() {
            o.on_peer_ban_score_adjustment(peer_address, score);
        }

        if score >= *self.p2p_config.ban_config.discouragement_threshold {
            let address = peer_address.as_bannable();
            self.discourage(address);
        }
    }

    fn bannable_peers_for_addr(&self, address: BannableAddress) -> Vec<PeerId> {
        self.peers
            .values()
            .filter_map(|peer| {
                if peer.peer_address.as_bannable() == address {
                    Some(peer.info.peer_id)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
    }

    fn ban(&mut self, address: BannableAddress, duration: Duration) {
        let to_disconnect = self.bannable_peers_for_addr(address);

        log::info!(
            "Banning {:?}, the following peers will be disconnected: {:?}",
            address,
            to_disconnect
        );

        self.peerdb.ban(address, duration);

        if let Some(o) = self.observer.as_mut() {
            o.on_peer_ban(address);
        }

        for peer_id in to_disconnect {
            self.disconnect(
                peer_id,
                PeerDisconnectionDbAction::Keep,
                Some(DisconnectionReason::AddressBanned),
                None,
            );
        }
    }

    fn discourage(&mut self, address: BannableAddress) {
        let to_disconnect = self.bannable_peers_for_addr(address);

        log::info!(
            "Discouraging {:?}, the following peers will be disconnected: {:?}",
            address,
            to_disconnect
        );

        self.peerdb.discourage(address);

        if let Some(o) = self.observer.as_mut() {
            o.on_peer_discouragement(address);
        }

        for peer_id in to_disconnect {
            self.disconnect(
                peer_id,
                PeerDisconnectionDbAction::Keep,
                Some(DisconnectionReason::AddressDiscouraged),
                None,
            );
        }
    }

    /// Try to initiate a new outbound connection
    ///
    /// This function doesn't block on the call but sends a command to the
    /// networking backend which then reports at some point in the future
    /// whether the connection failed or succeeded.
    fn try_connect(
        &mut self,
        address: SocketAddress,
        local_services_override: Option<Services>,
        peer_role: PeerRole,
    ) -> crate::Result<()> {
        ensure!(
            self.networking_enabled,
            P2pError::ConnectionValidationFailed(ConnectionValidationError::NetworkingDisabled),
        );

        ensure!(
            !self.pending_outbound_connects.contains_key(&address),
            P2pError::PeerError(PeerError::Pending(address.to_string())),
        );

        self.maybe_reject_because_already_connected(&address, peer_role)?;

        let bannable_address = address.as_bannable();
        let is_reserved = self.peerdb.is_reserved_node(&address);
        let is_banned = self.peerdb.is_address_banned(&bannable_address);
        let is_discouraged = self.peerdb.is_address_discouraged(&bannable_address);
        ensure!(
            !is_banned || is_reserved,
            P2pError::ConnectionValidationFailed(ConnectionValidationError::AddressBanned {
                address: address.to_string()
            }),
        );
        ensure!(
            !is_discouraged || is_reserved,
            P2pError::ConnectionValidationFailed(ConnectionValidationError::AddressDiscouraged {
                address: address.to_string()
            }),
        );

        self.peer_connectivity_handle.connect(address, local_services_override)?;

        Ok(())
    }

    /// Initiate a new outbound connection or send an error via `response_sender` if it's not possible.
    fn connect(&mut self, address: SocketAddress, outbound_connect_type: OutboundConnectType) {
        let block_relay_only = outbound_connect_type.block_relay_only();

        let local_services_override: Option<Services> = if block_relay_only {
            Some([Service::Blocks].as_slice().into())
        } else {
            None
        };

        let peer_role: PeerRole = (&outbound_connect_type).into();
        log::debug!("Trying a new outbound connection, address: {:?}, local_services_override: {:?}, peer_role: {:?}",
            address, local_services_override, peer_role);
        let res = self.try_connect(address, local_services_override, peer_role);

        match res {
            Ok(()) => {
                let old_value = self.pending_outbound_connects.insert(
                    address,
                    PendingConnect {
                        outbound_connect_type,
                    },
                );
                assert!(old_value.is_none());
            }
            Err(e) => {
                log::debug!("Outbound connection to {address:?} failed: {e}");
                match outbound_connect_type {
                    OutboundConnectType::Automatic {
                        block_relay_only: _,
                    }
                    | OutboundConnectType::Reserved
                    | OutboundConnectType::Feeler => {}
                    OutboundConnectType::Manual { response_sender } => {
                        response_sender.send(Err(e));
                    }
                }
            }
        }
    }

    // Try to disconnect a connected peer
    fn try_disconnect(
        &mut self,
        peer_id: PeerId,
        reason: Option<DisconnectionReason>,
    ) -> crate::Result<()> {
        ensure!(
            !self.pending_disconnects.contains_key(&peer_id),
            P2pError::PeerError(PeerError::Pending(peer_id.to_string())),
        );

        ensure!(
            self.peers.contains_key(&peer_id),
            P2pError::PeerError(PeerError::PeerDoesntExist),
        );

        self.peer_connectivity_handle.disconnect(peer_id, reason)?;

        Ok(())
    }

    /// Disconnect an existing connection (inbound or outbound)
    ///
    /// The decision to close the connection is made either by the user via RPC
    /// or by the [`PeerManager::heartbeat()`] function which has decided to cull
    /// this connection in favor of another potential connection.
    ///
    /// If the `response` channel is not empty, the peer is marked as disconnected by the user and no reconnect attempts are made.
    fn disconnect(
        &mut self,
        peer_id: PeerId,
        peerdb_action: PeerDisconnectionDbAction,
        reason: Option<DisconnectionReason>,
        response_sender: Option<oneshot_nofail::Sender<crate::Result<()>>>,
    ) {
        log::debug!("Disconnect peer {peer_id}");
        let res = self.try_disconnect(peer_id, reason);

        match res {
            Ok(()) => {
                let old_value = self.pending_disconnects.insert(
                    peer_id,
                    PendingDisconnect {
                        peerdb_action,
                        response_sender,
                    },
                );
                assert!(old_value.is_none());
            }
            Err(e) => {
                log::warn!("Disconnecting peer {peer_id} failed: {e}");
                if let Some(response_sender) = response_sender {
                    response_sender.send(Err(e));
                }
            }
        }
    }

    /// Check if the (inbound or outbound) peer connection can be accepted.
    ///
    /// For example, an inbound connection will not be accepted when the limit of inbound connections is reached.
    fn validate_connection(
        &mut self,
        address: &SocketAddress,
        peer_role: PeerRole,
        info: &PeerInfo,
    ) -> crate::Result<()> {
        ensure!(
            self.networking_enabled,
            P2pError::ConnectionValidationFailed(ConnectionValidationError::NetworkingDisabled),
        );

        info.check_compatibility(&self.chain_config)?;

        let is_peer_connected = self.is_peer_connected(info.peer_id);
        // This is a rather strange situation that should never happen.
        debug_assert!(!is_peer_connected);
        ensure!(
            !is_peer_connected,
            P2pError::PeerError(PeerError::PeerAlreadyExists(info.peer_id)),
        );

        // Note: for inbound connections, maybe_reject_because_already_connected always returns
        // Ok and for outbound ones we've already called it in try_connect. But new connections
        // might have appeared since try_connect was called, so the call below is not redundant.
        self.maybe_reject_because_already_connected(address, peer_role)?;

        // Note: for outbound connections, ban and discouragement statuses have already been
        // checked in try_connect, so when we do the checks here, they'll only work for
        // inbound connections. And since inbound connections from discouraged addresses are
        // allowed, we only check the banned status here.
        ensure!(
            !self.peerdb.is_address_banned(&address.as_bannable()),
            P2pError::ConnectionValidationFailed(ConnectionValidationError::AddressBanned {
                address: address.to_string()
            }),
        );

        ensure!(
            !info.common_services.is_empty(),
            P2pError::ConnectionValidationFailed(ConnectionValidationError::NoCommonServices),
        );

        match peer_role {
            PeerRole::Inbound => {
                // If the maximum number of inbound connections is reached,
                // the new inbound connection cannot be accepted even if it's valid.
                // Outbound peer count is not checked because the node initiates new connections
                // only when needed or from RPC requests.
                // TODO: Always allow connections from the whitelisted IPs
                if self.inbound_peer_count()
                    >= *self.p2p_config.peer_manager_config.max_inbound_connections
                {
                    if self.peerdb.is_address_discouraged(&address.as_bannable()) {
                        log::info!("Rejecting inbound connection from a discouraged address - too many peers");
                        return Err(P2pError::ConnectionValidationFailed(
                            ConnectionValidationError::TooManyInboundPeersAndThisOneIsDiscouraged,
                        ));
                    }

                    if !self.try_evict_random_inbound_connection() {
                        log::info!("Rejecting inbound connection - too many peers and none of them can be evicted");
                        return Err(P2pError::ConnectionValidationFailed(
                            ConnectionValidationError::TooManyInboundPeersAndCannotEvictAnyone,
                        ));
                    }
                }
            }

            PeerRole::OutboundReserved | PeerRole::OutboundManual | PeerRole::Feeler => {}

            PeerRole::OutboundFullRelay => {
                let needed_services: Services = (*self.p2p_config.node_type).into();
                utils::ensure!(
                    info.common_services == needed_services,
                    P2pError::ConnectionValidationFailed(
                        ConnectionValidationError::InsufficientServices {
                            needed_services,
                            available_services: info.common_services,
                        }
                    )
                );
            }

            PeerRole::OutboundBlockRelay => {
                let needed_services: Services = [Service::Blocks].as_slice().into();
                utils::ensure!(
                    info.common_services == needed_services,
                    P2pError::ConnectionValidationFailed(
                        ConnectionValidationError::InsufficientServices {
                            needed_services,
                            available_services: info.common_services,
                        }
                    )
                );
            }
        }

        Ok(())
    }

    fn eviction_candidates(&self, peer_role: PeerRole) -> Vec<peers_eviction::EvictionCandidate> {
        let now = self.time_getter.get_time();
        self.peers
            .values()
            .filter(|peer| {
                peer.peer_role == peer_role
                    && !self.pending_disconnects.contains_key(&peer.info.peer_id)
            })
            .map(|peer| {
                let addr = peer.peer_address.as_bannable();
                peers_eviction::EvictionCandidate::new(
                    peer,
                    &self.peer_eviction_random_state,
                    now,
                    self.peerdb.is_address_banned_or_discouraged(&addr),
                )
            })
            .collect()
    }

    /// Try to disconnect a random inbound peer, making it difficult for attackers to control all inbound peers.
    /// It's called when a new inbound connection is received, but the connection limit has been reached.
    /// Returns true if a random peer has been disconnected.
    fn try_evict_random_inbound_connection(&mut self) -> bool {
        if let Some(peer_id) = peers_eviction::select_for_eviction_inbound(
            self.eviction_candidates(PeerRole::Inbound),
            &self.p2p_config.peer_manager_config,
            &mut make_pseudo_rng(),
        ) {
            log::info!("Inbound peer {peer_id} is selected for eviction");
            self.disconnect(
                peer_id,
                PeerDisconnectionDbAction::Keep,
                Some(DisconnectionReason::PeerEvicted),
                None,
            );
            true
        } else {
            false
        }
    }

    /// If there are too many outbound block relay peers, find and disconnect the "worst" one.
    fn evict_block_relay_peer(&mut self) {
        if let Some(peer_id) = peers_eviction::select_for_eviction_block_relay(
            self.eviction_candidates(PeerRole::OutboundBlockRelay),
            &self.p2p_config.peer_manager_config,
            self.time_getter.get_time(),
            &mut make_pseudo_rng(),
        ) {
            log::info!("Block relay peer {peer_id} is selected for eviction");
            self.disconnect(
                peer_id,
                PeerDisconnectionDbAction::Keep,
                Some(DisconnectionReason::PeerEvicted),
                None,
            );
        }
    }

    /// If there are too many outbound full relay peers, find and disconnect the "worst" one.
    fn evict_full_relay_peer(&mut self) {
        if let Some(peer_id) = peers_eviction::select_for_eviction_full_relay(
            self.eviction_candidates(PeerRole::OutboundFullRelay),
            &self.p2p_config.peer_manager_config,
            self.time_getter.get_time(),
            &mut make_pseudo_rng(),
        ) {
            log::info!("Full relay peer {peer_id} is selected for eviction");
            self.disconnect(
                peer_id,
                PeerDisconnectionDbAction::Keep,
                Some(DisconnectionReason::PeerEvicted),
                None,
            );
        }
    }

    /// Should we load addresses from this peer?
    fn should_load_addresses_from(peer_role: PeerRole) -> bool {
        // Load addresses only from outbound peers, like it's done in Bitcoin Core
        match peer_role {
            PeerRole::OutboundFullRelay | PeerRole::OutboundReserved | PeerRole::OutboundManual => {
                true
            }
            PeerRole::Inbound | PeerRole::OutboundBlockRelay | PeerRole::Feeler => false,
        }
    }

    /// Should we send addresses to this peer if it requests them?
    fn should_send_addresses_to(peer_role: PeerRole) -> bool {
        // Send addresses only to inbound peers, like it's done in Bitcoin Core
        match peer_role {
            PeerRole::Inbound => true,
            PeerRole::OutboundFullRelay
            | PeerRole::OutboundBlockRelay
            | PeerRole::OutboundReserved
            | PeerRole::OutboundManual
            | PeerRole::Feeler => false,
        }
    }

    /// Try accept new connection
    ///
    /// The event is received from the networking backend and it's either a result of an incoming
    /// connection from a remote peer or a response to an outbound connection that was initiated
    /// by the node as result of the peer manager maintenance.
    fn try_accept_connection(
        &mut self,
        peer_address: SocketAddress,
        bind_address: SocketAddress,
        peer_role: PeerRole,
        info: PeerInfo,
        node_address_as_seen_by_peer: Option<PeerAddress>,
    ) -> crate::Result<()> {
        let peer_id = info.peer_id;

        self.validate_connection(&peer_address, peer_role, &info)?;

        self.peer_connectivity_handle.accept(peer_id)?;

        log::info!(
            "New peer accepted, peer_id: {}, address: {:?}, role: {:?}, protocol_version: {:?}, user agent: {} v{}",
            peer_id,
            peer_address,
            peer_role,
            info.protocol_version,
            info.user_agent,
            info.software_version
        );

        if info.common_services.has_service(Service::PeerAddresses) {
            self.subscribed_to_peer_addresses.insert(info.peer_id);
        }

        if Self::should_load_addresses_from(peer_role) {
            log::debug!("Asking peer {peer_id} for addresses");
            Self::send_peer_message(
                &mut self.peer_connectivity_handle,
                peer_id,
                PeerManagerMessage::AddrListRequest(AddrListRequest {}),
            );
        }

        let address_rate_limiter = RateLimiter::new(
            self.time_getter.get_time(),
            MAX_ADDR_RATE_PER_SECOND,
            ADDR_RATE_INITIAL_SIZE,
            ADDR_RATE_BUCKET_SIZE,
        );

        let announced_addresses = RollingBloomFilter::new(
            PEER_ADDRESSES_ROLLING_BLOOM_FILTER_SIZE,
            PEER_ADDRESSES_ROLLING_BLOOM_FPP,
            &mut make_pseudo_rng(),
        );

        let discovered_own_address = self.discover_own_address(
            peer_id,
            peer_role,
            info.common_services,
            node_address_as_seen_by_peer,
        );

        let peer = PeerContext {
            created_at: self.time_getter.get_time(),
            info,
            peer_address,
            bind_address,
            peer_role,
            score: 0,
            sent_ping: None,
            ping_last: None,
            ping_min: None,
            addr_list_req_received: SetFlag::new(),
            addr_list_resp_received: SetFlag::new(),
            announced_addresses,
            address_rate_limiter,
            discovered_own_address,
            last_tip_block_time: None,
            last_tx_time: None,
            block_sync_status: PeerBlockSyncStatus::new(),
        };

        Self::send_own_address_to_peer(&mut self.peer_connectivity_handle, &peer);

        let old_value = self.peers.insert(peer_id, peer);
        assert!(old_value.is_none());

        if peer_role.is_outbound() {
            self.peerdb.outbound_peer_connected(peer_address);
        }

        if peer_role == PeerRole::OutboundBlockRelay {
            let anchor_addresses = self
                .peers
                .values()
                .filter_map(|peer| match peer.peer_role {
                    PeerRole::Inbound
                    | PeerRole::OutboundFullRelay
                    | PeerRole::OutboundReserved
                    | PeerRole::OutboundManual
                    | PeerRole::Feeler => None,
                    PeerRole::OutboundBlockRelay => Some(peer.peer_address),
                })
                // Note: there may be more than outbound_block_relay_count block relay connections
                // at a given moment, but the extra ones will soon be evicted. Since connections
                // with smaller peer ids are less likely to be evicted, we choose them here.
                .take(*self.p2p_config.peer_manager_config.outbound_block_relay_count)
                .collect();
            self.peerdb.set_anchors(anchor_addresses);
        }

        if let Some(o) = self.observer.as_mut() {
            o.on_connection_accepted(peer_address, peer_role)
        }

        Ok(())
    }

    fn accept_connection(
        &mut self,
        peer_address: SocketAddress,
        bind_address: SocketAddress,
        conn_dir: ConnectionDirection,
        info: PeerInfo,
        node_address_as_seen_by_peer: Option<PeerAddress>,
    ) {
        let peer_id = info.peer_id;

        let (peer_role, response_sender) = match conn_dir {
            ConnectionDirection::Inbound => (PeerRole::Inbound, None),
            ConnectionDirection::Outbound => {
                let pending_connect = self.pending_outbound_connects.remove(&peer_address).expect(
                    "the address must be present in pending_outbound_connects (accept_connection)",
                );
                let role = (&pending_connect.outbound_connect_type).into();
                let response_sender = match pending_connect.outbound_connect_type {
                    OutboundConnectType::Automatic {
                        block_relay_only: _,
                    }
                    | OutboundConnectType::Reserved
                    | OutboundConnectType::Feeler => None,
                    OutboundConnectType::Manual { response_sender } => Some(response_sender),
                };

                (role, response_sender)
            }
        };

        let accept_res = self.try_accept_connection(
            peer_address,
            bind_address,
            peer_role,
            info,
            node_address_as_seen_by_peer,
        );

        if let Err(accept_err) = &accept_res {
            log::debug!("Connection rejected for peer {peer_id}: {accept_err}");

            let disconnection_reason = DisconnectionReason::from_error(accept_err);

            // Disconnect should always succeed unless the node is shutting down.
            // But at this moment there is a possibility for backend to be shut down
            // before peer manager, at least in tests, so we don't "expect" and log
            // the error instead.
            // TODO: investigate why peer manager can be shut down before the backend (it shouldn't
            // be this way according to an earlier comment).
            // TODO: we probably shouldn't use "log::error" if the error happened during
            // shutdown. Probably, peer manager should accept the "shutdown" flag, like other
            // p2p components do, and ignore/log::info the errors it it's set (this also applies
            // to other places, search for "log::error" in this file).
            let disconnect_result =
                self.peer_connectivity_handle.disconnect(peer_id, disconnection_reason);
            if let Err(err) = disconnect_result {
                log::error!("Disconnect failed unexpectedly: {err:?}");
            }

            if peer_role.is_outbound() {
                self.peerdb.report_outbound_failure(peer_address);
            }
        } else if peer_role == PeerRole::Feeler {
            self.disconnect(
                peer_id,
                PeerDisconnectionDbAction::Keep,
                Some(DisconnectionReason::FeelerConnection),
                None,
            );
        }

        if let Some(response_sender) = response_sender {
            response_sender.send(accept_res);
        }
    }

    /// Handle outbound connection error
    ///
    /// The outbound connection was dialed successfully but the remote either did not respond
    /// (at all or in time) or it didn't support the handshaking which forced the connection closed.
    ///
    /// If the connection was initiated by the user via RPC, inform them that the connection failed.
    /// Inform the [`crate::peer_manager::peerdb::PeerDb`] about the address failure so it knows to
    /// update its own records.
    fn handle_outbound_error(&mut self, address: SocketAddress, error: P2pError) {
        self.peerdb.report_outbound_failure(address);

        let PendingConnect {
            outbound_connect_type,
        } = self.pending_outbound_connects.remove(&address).expect(
            "the address must be present in pending_outbound_connects (handle_outbound_error)",
        );
        match outbound_connect_type {
            OutboundConnectType::Automatic {
                block_relay_only: _,
            }
            | OutboundConnectType::Reserved
            | OutboundConnectType::Feeler => {}
            OutboundConnectType::Manual { response_sender } => {
                response_sender.send(Err(error));
            }
        }
    }

    /// The connection to a remote peer is reported as closed.
    ///
    /// This can happen when the remote peer has dropped its connection
    /// or if a disconnect request has been sent by PeerManager to the backend.
    fn connection_closed(&mut self, peer_id: PeerId) {
        // The peer will not be in `peers` for rejected connections
        if let Some(peer) = self.peers.remove(&peer_id) {
            log::info!(
                "Peer disconnected, peer_id: {}, address: {:?}",
                peer.info.peer_id,
                peer.peer_address
            );

            if peer.peer_role.is_outbound() {
                self.peerdb.outbound_peer_disconnected(peer.peer_address);
            }

            if let Some(PendingDisconnect {
                peerdb_action,
                response_sender,
            }) = self.pending_disconnects.remove(&peer_id)
            {
                match peerdb_action {
                    PeerDisconnectionDbAction::Keep => {}
                    PeerDisconnectionDbAction::RemoveIfOutbound => {
                        if peer.peer_role.is_outbound() {
                            self.peerdb.remove_address(&peer.peer_address);
                        }
                    }
                }

                if let Some(response_sender) = response_sender {
                    response_sender.send(Ok(()));
                }
            }

            self.subscribed_to_peer_addresses.remove(&peer_id);
        }
    }

    fn send_peer_message(
        peer_connectivity_handle: &mut T::ConnectivityHandle,
        peer_id: PeerId,
        message: PeerManagerMessage,
    ) {
        // `send_message` should not fail, but even if it does, the error can be ignored
        // because sending messages over the network does not guarantee that they will be received
        let res = peer_connectivity_handle.send_message(peer_id, message);
        if let Err(err) = res {
            log::error!("send_message failed unexpectedly: {err:?}");
        }
    }

    /// Fill PeerDb with addresses from the DNS seed servers
    async fn query_dns_seed(&mut self) {
        let addresses = self.dns_seed.obtain_addresses().await;

        let mut new_addr_count = 0;
        for addr in &addresses {
            if self.peerdb.peer_discovered(*addr) {
                new_addr_count += 1;
            }
        }

        log::info!(
            "Dns seed queried, {} total addresses obtained, {} of which are new",
            addresses.len(),
            new_addr_count
        );
        log::debug!("Addresses from the dns server: {addresses:?}");

        self.last_dns_query_time = Some(self.time_getter.get_time());
    }

    fn peer_addresses_iter(&self) -> impl Iterator<Item = (SocketAddress, PeerRole)> + '_ {
        let pending = self.pending_outbound_connects.iter().map(|(addr, pending_conn)| {
            let role = (&pending_conn.outbound_connect_type).into();
            (*addr, role)
        });
        let connected =
            self.peers.values().map(|peer_ctx| (peer_ctx.peer_address, peer_ctx.peer_role));
        connected.chain(pending)
    }

    /// Maintains the peer manager state.
    ///
    /// `PeerManager::heartbeat()` is called every time a network/control event is received
    /// or the heartbeat timer of the event loop expires. In other words, the peer manager state
    /// is checked and updated at least once every 30 seconds. In high-traffic scenarios the
    /// update interval is clamped to a sensible lower bound. `PeerManager` will keep track of
    /// when it last updated its own state and if the time since last update is less than the
    /// configured lower bound, *heartbeat* won't be called.
    ///
    /// This function maintains the overall connectivity state of peers by culling
    /// low-reputation peers and establishing new connections with peers that have higher
    /// reputation. It also updates peer scores and forgets those peers that are no longer needed.
    ///
    /// The process starts by first checking if the number of active connections is less than
    /// the number of desired connections and there are available peers, the function tries to
    /// establish new connections. After that it updates the peer scores and discards any records
    /// that no longer need to be stored.
    fn heartbeat(&mut self) {
        // Expired banned and discouraged addresses are dropped here.
        self.peerdb.heartbeat();

        if self.networking_enabled {
            self.establish_new_connections();

            self.evict_block_relay_peer();
            self.evict_full_relay_peer();
        }

        self.last_heartbeat_time = Some(self.time_getter.get_time());

        if let Some(o) = self.observer.as_mut() {
            o.on_heartbeat();
        }
    }

    fn establish_new_connections(&mut self) {
        let mut cur_outbound_full_relay_conn_count = 0;
        let mut cur_outbound_block_relay_conn_count = 0;
        let mut cur_feeler_conn_count = 0;
        let mut cur_outbound_conn_addr_groups = BTreeSet::new();
        let mut cur_conn_ip_port_to_role_map = BTreeMap::new();

        for (addr, role) in self.peer_addresses_iter() {
            let addr_group = AddressGroup::from_peer_address(&addr.as_peer_address());

            match role {
                PeerRole::Inbound => {}
                PeerRole::OutboundReserved | PeerRole::OutboundManual => {
                    cur_outbound_conn_addr_groups.insert(addr_group);
                }
                PeerRole::OutboundFullRelay => {
                    cur_outbound_full_relay_conn_count += 1;
                    cur_outbound_conn_addr_groups.insert(addr_group);
                }
                PeerRole::OutboundBlockRelay => {
                    cur_outbound_block_relay_conn_count += 1;
                    cur_outbound_conn_addr_groups.insert(addr_group);
                }
                PeerRole::Feeler => {
                    cur_feeler_conn_count += 1;
                }
            }

            let socket_addr = addr.socket_addr();
            cur_conn_ip_port_to_role_map.insert((socket_addr.ip(), socket_addr.port()), role);
        }

        let needed_outbound_full_relay_conn_count = {
            let extra_conn_count = if self.tip_is_stale() {
                *self.p2p_config.peer_manager_config.outbound_full_relay_extra_count
            } else {
                0
            };

            (*self.p2p_config.peer_manager_config.outbound_full_relay_count + extra_conn_count)
                .saturating_sub(cur_outbound_full_relay_conn_count)
        };

        let new_full_relay_conn_addresses = self.peerdb.select_non_reserved_outbound_addresses(
            &cur_outbound_conn_addr_groups,
            &|addr| {
                self.allow_new_outbound_connection(
                    &cur_conn_ip_port_to_role_map,
                    addr,
                    PeerRole::OutboundFullRelay,
                )
            },
            needed_outbound_full_relay_conn_count,
        );

        log::debug!(
            "Need to establish {} full relay connection(s); selected addresses: {:?}",
            needed_outbound_full_relay_conn_count,
            new_full_relay_conn_addresses
        );

        // TODO: in bitcoin they also try to create an extra outbound full relay connection
        // to an address in a reachable network in which there are no outbound full relay or
        // manual connections (see CConnman::MaybePickPreferredNetwork for reference).
        // See https://github.com/mintlayer/mintlayer-core/issues/1433

        for address in &new_full_relay_conn_addresses {
            let addr_group = AddressGroup::from_peer_address(&address.as_peer_address());
            cur_outbound_conn_addr_groups.insert(addr_group);

            self.connect(
                *address,
                OutboundConnectType::Automatic {
                    block_relay_only: false,
                },
            );
        }

        let needed_outbound_block_relay_conn_count =
            (*self.p2p_config.peer_manager_config.outbound_block_relay_count
                + *self.p2p_config.peer_manager_config.outbound_block_relay_extra_count)
                .saturating_sub(cur_outbound_block_relay_conn_count);

        let new_block_relay_conn_addresses = self.peerdb.select_non_reserved_outbound_addresses(
            &cur_outbound_conn_addr_groups,
            &|addr| {
                self.allow_new_outbound_connection(
                    &cur_conn_ip_port_to_role_map,
                    addr,
                    PeerRole::OutboundBlockRelay,
                )
            },
            needed_outbound_block_relay_conn_count,
        );

        log::debug!(
            "Need to establish {} block relay connection(s); selected addresses: {:?}",
            needed_outbound_block_relay_conn_count,
            new_block_relay_conn_addresses
        );

        for address in &new_block_relay_conn_addresses {
            self.connect(
                *address,
                OutboundConnectType::Automatic {
                    block_relay_only: true,
                },
            );
        }

        let cur_pending_outbound_conn_addresses =
            self.pending_outbound_connects.keys().cloned().collect::<BTreeSet<_>>();
        let new_reserved_conn_addresses = self.peerdb.select_reserved_outbound_addresses(&|addr| {
            !cur_pending_outbound_conn_addresses.contains(addr)
                && self.allow_new_outbound_connection(
                    &cur_conn_ip_port_to_role_map,
                    addr,
                    PeerRole::OutboundReserved,
                )
        });

        log::debug!(
            "Need to establish connections to these reserved addresses: {:?}",
            new_reserved_conn_addresses
        );

        for address in &new_reserved_conn_addresses {
            self.connect(*address, OutboundConnectType::Reserved);
        }

        let now = self.time_getter.get_time();
        if *self.p2p_config.peer_manager_config.enable_feeler_connections
            && new_full_relay_conn_addresses.is_empty()
            && cur_feeler_conn_count == 0
            && now >= self.next_feeler_connection_time
        {
            if let Some(address) =
                self.peerdb.select_non_reserved_outbound_address_from_new_addr_table()
            {
                self.connect(address, OutboundConnectType::Feeler);
                self.next_feeler_connection_time =
                    Self::choose_next_feeler_connection_time(&self.p2p_config, now);
            }
        }
    }

    fn handle_incoming_message(&mut self, peer: PeerId, message: PeerManagerMessage) {
        match message {
            PeerManagerMessage::AddrListRequest(_) => self.handle_addr_list_request(peer),
            PeerManagerMessage::AnnounceAddrRequest(r) => {
                self.handle_announce_addr_request(peer, r.address)
            }
            PeerManagerMessage::PingRequest(r) => self.handle_ping_request(peer, r.nonce),
            PeerManagerMessage::AddrListResponse(r) => {
                self.handle_addr_list_response(peer, r.addresses)
            }
            PeerManagerMessage::PingResponse(r) => self.handle_ping_response(peer, r.nonce),
            PeerManagerMessage::WillDisconnect(msg) => {
                self.handle_will_disconnect_messgae(peer, msg)
            }
        }
    }

    fn handle_announce_addr_request(&mut self, peer_id: PeerId, address: PeerAddress) {
        if let Some(address) =
            address.as_discoverable_socket_address(*self.p2p_config.allow_discover_private_ips)
        {
            let peer = self
                .peers
                .get_mut(&peer_id)
                .expect("peer sending AnnounceAddrRequest must be known");
            if !peer.address_rate_limiter.accept(self.time_getter.get_time()) {
                log::debug!("Address announcement is rate limited from peer {peer_id}");
                return;
            }

            peer.announced_addresses.insert(&address, &mut make_pseudo_rng());

            self.peerdb.peer_discovered(address);

            if !self.peerdb.is_address_banned_or_discouraged(&address.as_bannable()) {
                let peer_ids = self
                    .subscribed_to_peer_addresses
                    .iter()
                    .cloned()
                    .choose_multiple(&mut make_pseudo_rng(), PEER_ADDRESS_RESEND_COUNT);
                for new_peer_id in peer_ids {
                    self.announce_address(new_peer_id, address);
                }
            }
        }
    }

    fn handle_addr_list_request(&mut self, peer_id: PeerId) {
        let peer = self.peers.get_mut(&peer_id).expect("peer must be known");
        // Only one request allowed to reduce load in case of DoS attacks
        if !Self::should_send_addresses_to(peer.peer_role)
            || peer.addr_list_req_received.test_and_set()
        {
            log::warn!("Ignore unexpected address list request from peer {peer_id}");
            return;
        }

        let max_addr_count = *self.p2p_config.protocol_config.max_addr_list_response_address_count;

        let now = self.time_getter.get_time();
        let addresses = self
            .addr_list_response_cache
            .get_or_create(peer, now, || {
                self.peerdb
                    .known_addresses()
                    .filter_map(|address| {
                        let peer_addr = address.as_peer_address();
                        let bannable_addr = address.as_bannable();
                        if Self::is_peer_address_discoverable(&peer_addr, &self.p2p_config)
                            && !self.peerdb.is_address_banned_or_discouraged(&bannable_addr)
                        {
                            Some(peer_addr)
                        } else {
                            None
                        }
                    })
                    .choose_multiple(&mut make_pseudo_rng(), max_addr_count)
            })
            // Note: some of the addresses may have become banned or discouraged after they've been
            // cached. It's not clear whether it's better to filter them out here, which will
            // reveal to peers what addresses we've banned or discouraged, or keep them as is.
            // But it's probably not that important.
            .clone();

        assert!(addresses.len() <= max_addr_count);

        Self::send_peer_message(
            &mut self.peer_connectivity_handle,
            peer_id,
            PeerManagerMessage::AddrListResponse(AddrListResponse { addresses }),
        );
    }

    fn try_handle_addr_list_response(
        &mut self,
        peer_id: PeerId,
        addresses: Vec<PeerAddress>,
    ) -> crate::Result<()> {
        log::debug!(
            "[peer id = {peer_id}] Handling addr list response, address count = {}",
            addresses.len()
        );

        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;
        ensure!(
            addresses.len()
                <= *self.p2p_config.protocol_config.max_addr_list_response_address_count,
            P2pError::ProtocolError(ProtocolError::AddressListLimitExceeded)
        );
        ensure!(
            Self::should_load_addresses_from(peer.peer_role)
                && !peer.addr_list_resp_received.test_and_set(),
            P2pError::ProtocolError(ProtocolError::UnexpectedMessage(
                "AddrListResponse".to_owned()
            ))
        );

        for address in &addresses {
            if let Some(address) =
                address.as_discoverable_socket_address(*self.p2p_config.allow_discover_private_ips)
            {
                self.peerdb.peer_discovered(address);
            }
        }

        Ok(())
    }

    fn handle_addr_list_response(&mut self, peer_id: PeerId, addresses: Vec<PeerAddress>) {
        let res = self.try_handle_addr_list_response(peer_id, addresses);
        if let Err(err) = res {
            self.adjust_peer_score(peer_id, err.ban_score(), &err);
        }
    }

    fn handle_ping_request(&mut self, peer: PeerId, nonce: u64) {
        Self::send_peer_message(
            &mut self.peer_connectivity_handle,
            peer,
            PeerManagerMessage::PingResponse(PingResponse { nonce }),
        );
    }

    fn handle_ping_response(&mut self, peer_id: PeerId, nonce: u64) {
        if let Some(peer) = self.peers.get_mut(&peer_id) {
            if let Some(sent_ping) = peer.sent_ping.as_mut() {
                if sent_ping.nonce == nonce {
                    // Correct reply received, clear pending request and update ping times

                    let ping_time_last =
                        (self.time_getter.get_time() - sent_ping.timestamp).unwrap_or_default();

                    let ping_time_min = peer.ping_min.map_or(ping_time_last, |ping_time_min| {
                        std::cmp::min(ping_time_min, ping_time_last)
                    });

                    peer.sent_ping = None;
                    peer.ping_last = Some(ping_time_last);
                    peer.ping_min = Some(ping_time_min);
                } else {
                    log::debug!(
                        "Wrong nonce in ping response from peer {}, received: {}, expected: {}",
                        peer_id,
                        nonce,
                        sent_ping.nonce,
                    );
                }
            } else {
                log::debug!("Unexpected ping response received from peer {}", peer_id);
            }
        }
    }

    fn handle_will_disconnect_messgae(&mut self, peer_id: PeerId, msg: WillDisconnectMessage) {
        log::info!(
            "Peer {peer_id} is going to disconnect us with the reason: {}",
            msg.reason
        );

        // Initiate the disconnection as well, to prevent malfunctioning/malicious peers from
        // flooding us with "WillDisconnect", while not actually disconnecting.
        self.disconnect(peer_id, PeerDisconnectionDbAction::Keep, None, None);
    }

    /// Handle control event.
    ///
    /// Handle events from an outside controller (rpc, for example) that sets/gets values for PeerManager.
    fn handle_control_event(&mut self, event: PeerManagerEvent) {
        match event {
            PeerManagerEvent::Connect(address, response_sender) => {
                let address = ip_or_socket_address_to_peer_address(&address, &self.chain_config);
                self.connect(address, OutboundConnectType::Manual { response_sender });
            }
            PeerManagerEvent::Disconnect(peer_id, peerdb_action, reason, response_sender) => {
                self.disconnect(peer_id, peerdb_action, reason, Some(response_sender));
            }
            PeerManagerEvent::AdjustPeerScore {
                peer_id,
                adjust_by,
                reason,
                response_sender,
            } => {
                self.adjust_peer_score(peer_id, adjust_by, &reason);
                response_sender.send(Ok(()));
            }
            PeerManagerEvent::NewTipReceived { peer_id, block_id } => {
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    log::debug!("New tip {block_id} received from peer {peer_id}");
                    peer.last_tip_block_time = Some(self.time_getter.get_time());
                }
            }
            PeerManagerEvent::NewChainstateTip(block_id) => {
                log::debug!("New tip {block_id} added to chainstate");
                self.last_chainstate_tip_block_time = Some(self.time_getter.get_time());
            }
            PeerManagerEvent::NewValidTransactionReceived { peer_id, txid } => {
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    log::debug!("New transaction {txid} received from peer {peer_id}");
                    peer.last_tx_time = Some(self.time_getter.get_time());
                }
            }
            PeerManagerEvent::PeerBlockSyncStatusUpdate {
                peer_id,
                new_status: status,
            } => {
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    log::debug!("Block sync status update received from peer {peer_id}, new status is {status:?}");
                    peer.block_sync_status = status;
                }
            }
            PeerManagerEvent::GetPeerCount(response_sender) => {
                response_sender.send(self.active_peer_count());
            }
            PeerManagerEvent::GetBindAddresses(response_sender) => {
                let addr = self.peer_connectivity_handle.local_addresses().to_vec();
                response_sender.send(addr);
            }
            PeerManagerEvent::GetConnectedPeers(response_sender) => {
                let peers = self.get_connected_peers();
                response_sender.send(peers);
            }
            PeerManagerEvent::GetReserved(response_sender) => {
                response_sender.send(self.peerdb.get_reserved_nodes().collect())
            }
            PeerManagerEvent::AddReserved(address, response_sender) => {
                let address = ip_or_socket_address_to_peer_address(&address, &self.chain_config);
                self.peerdb.add_reserved_node(address);
                if self.networking_enabled {
                    // Initiate new outbound connection without waiting for `heartbeat`
                    self.connect(address, OutboundConnectType::Reserved);
                }
                response_sender.send(Ok(()));
            }
            PeerManagerEvent::RemoveReserved(address, response_sender) => {
                let address = ip_or_socket_address_to_peer_address(&address, &self.chain_config);
                self.peerdb.remove_reserved_node(address);
                response_sender.send(Ok(()));
            }
            PeerManagerEvent::ListBanned(response_sender) => {
                response_sender.send(self.peerdb.list_banned().collect())
            }
            PeerManagerEvent::Ban(address, duration, response_sender) => {
                self.ban(address, duration);
                response_sender.send(Ok(()));
            }
            PeerManagerEvent::Unban(address, response_sender) => {
                self.peerdb.unban(&address);
                response_sender.send(Ok(()));
            }
            PeerManagerEvent::ListDiscouraged(response_sender) => {
                response_sender.send(self.peerdb.list_discouraged().collect())
            }
            PeerManagerEvent::Undiscourage(address, response_sender) => {
                self.peerdb.undiscourage(&address);
                response_sender.send(Ok(()));
            }
            PeerManagerEvent::EnableNetworking {
                enable,
                response_sender,
            } => {
                response_sender.send(self.enable_networking(enable));
            }
            PeerManagerEvent::GenericQuery(query_func) => {
                query_func(self);
            }

            #[cfg(test)]
            PeerManagerEvent::GenericMut(mut_func) => {
                mut_func(self);
            }
        }
    }

    /// Handle connectivity event
    fn handle_connectivity_event(&mut self, event: ConnectivityEvent) {
        match event {
            ConnectivityEvent::Message { peer_id, message } => {
                self.handle_incoming_message(peer_id, message);
            }
            ConnectivityEvent::InboundAccepted {
                peer_address,
                bind_address,
                peer_info,
                node_address_as_seen_by_peer,
            } => {
                self.accept_connection(
                    peer_address,
                    bind_address,
                    ConnectionDirection::Inbound,
                    peer_info,
                    node_address_as_seen_by_peer,
                );
            }
            ConnectivityEvent::OutboundAccepted {
                peer_address,
                bind_address,
                peer_info,
                node_address_as_seen_by_peer,
            } => {
                self.accept_connection(
                    peer_address,
                    bind_address,
                    ConnectionDirection::Outbound,
                    peer_info,
                    node_address_as_seen_by_peer,
                );
            }
            ConnectivityEvent::ConnectionClosed { peer_id } => {
                self.connection_closed(peer_id);
            }
            ConnectivityEvent::ConnectionError {
                peer_address,
                error,
            } => {
                self.handle_outbound_error(peer_address, error);
            }
            ConnectivityEvent::Misbehaved { peer_id, error } => {
                self.adjust_peer_score(peer_id, error.ban_score(), &error);
            }
            ConnectivityEvent::MisbehavedOnHandshake {
                peer_address,
                error,
            } => {
                self.adjust_peer_score_on_failed_handshake(peer_address, error.ban_score(), &error);
            }
        }
    }

    /// Get the number of active peers
    fn active_peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Returns short info about all connected peers
    fn get_connected_peers(&self) -> Vec<ConnectedPeer> {
        let now = self.time_getter.get_time();
        self.peers
            .values()
            .map(|context| ConnectedPeer {
                peer_id: context.info.peer_id,
                address: context.peer_address,
                peer_role: context.peer_role,
                ban_score: context.score,
                user_agent: context.info.user_agent.to_string(),
                software_version: context.info.software_version.to_string(),
                ping_wait: context.sent_ping.as_ref().map(|sent_ping| {
                    duration_to_int(&(now - sent_ping.timestamp).unwrap_or_default())
                        .expect("valid timestamp expected (ping_wait)")
                }),
                ping_last: context.ping_last.map(|time| {
                    duration_to_int(&time).expect("valid timestamp expected (ping_last)")
                }),
                ping_min: context.ping_min.map(|time| {
                    duration_to_int(&time).expect("valid timestamp expected (ping_min)")
                }),
                last_tip_block_time: context
                    .last_tip_block_time
                    .map(|time| time.as_secs_since_epoch()),
            })
            .collect()
    }

    /// Checks if the peer is in active state
    fn is_peer_connected(&self, peer_id: PeerId) -> bool {
        self.peers.contains_key(&peer_id)
    }

    // Return an error if a connection to the specified address already exists and it prevents us
    // from establishing another connection to the same address with the connection type determined
    // by `new_peer_role`.
    fn maybe_reject_because_already_connected(
        &self,
        new_peer_addr: &SocketAddress,
        new_peer_role: PeerRole,
    ) -> crate::Result<()> {
        match new_peer_role {
            // Don't reject inbound connections. The address will have a random port number anyway,
            // so we won't be able to tell whether the connections come from the same node or not.
            PeerRole::Inbound
            // Don't reject feeler connections either.
            | PeerRole::Feeler => {
                return Ok(());
            }
            PeerRole::OutboundFullRelay
            | PeerRole::OutboundBlockRelay
            | PeerRole::OutboundReserved
            | PeerRole::OutboundManual => {}
        }

        let conflicting_connection =
            self.peer_addresses_iter().find(|(existing_peer_addr, existing_peer_role)| {
                // If the ip addresses are different, allow the connection.
                if existing_peer_addr.ip_addr() != new_peer_addr.ip_addr() {
                    return false;
                }

                !self.may_allow_outbound_connection_to_existing_ip(
                    existing_peer_addr.socket_addr().port(),
                    *existing_peer_role,
                    new_peer_addr.socket_addr().port(),
                    new_peer_role,
                )
            });

        if let Some((existing_peer_addr, existing_peer_role)) = conflicting_connection {
            Err(P2pError::PeerError(PeerError::AlreadyConnected {
                existing_peer_addr,
                existing_peer_role,
                new_peer_addr: *new_peer_addr,
                new_peer_role,
            }))
        } else {
            Ok(())
        }
    }

    /// Return true if the specified `new_peer_addr` can be used for a new outbound connection.
    ///
    /// This is basically a replacement for `maybe_reject_because_already_connected` that
    /// is used when selecting addresses for new automatic outbound connections; it will be
    /// called for every address in peerdb, so we want to avoid the linear complexity of
    /// `maybe_reject_because_already_connected`.
    /// Note that calling this function mainly serves as an optimization - we don't want to select
    /// addresses that will be rejected anyway when we'll try to connect to them.
    fn allow_new_outbound_connection(
        &self,
        // Note: we use the (ip_addr, port) pair as a key instead of SocketAddress to ensure
        // that the keys are always sorted first by the ip and then by port.
        existing_connections: &BTreeMap<(IpAddr, /*port:*/ u16), PeerRole>,
        new_peer_addr: &SocketAddress,
        new_peer_role: PeerRole,
    ) -> bool {
        assert!(new_peer_role.is_outbound());

        let new_peer_ip = new_peer_addr.socket_addr().ip();
        let new_peer_port = new_peer_addr.socket_addr().port();
        existing_connections.range((new_peer_ip, 0)..=(new_peer_ip, u16::MAX)).all(
            |((_, existing_peer_port), existing_peer_role)| {
                self.may_allow_outbound_connection_to_existing_ip(
                    *existing_peer_port,
                    *existing_peer_role,
                    new_peer_port,
                    new_peer_role,
                )
            },
        )
    }

    /// This function is supposed to be called for every existing peer whose ip address
    /// equals the ip address of some "new peer"; it returns true if a connection to the new peer
    /// *may* be allowed. If it returns true for all such existing peers, then the connection
    /// will be allowed.
    fn may_allow_outbound_connection_to_existing_ip(
        &self,
        existing_peer_port: u16,
        existing_peer_role: PeerRole,
        new_peer_port: u16,
        new_peer_role: PeerRole,
    ) -> bool {
        assert!(new_peer_role.is_outbound());

        if existing_peer_port == new_peer_port {
            // Can't have multiple connections to the same socket address.
            return false;
        }

        // Allow the connection if explicitly told to do so.
        if *self.p2p_config.peer_manager_config.allow_same_ip_connections {
            return true;
        }

        if existing_peer_role.is_outbound() {
            // Outbound connections to different socket addresses are ok.
            return true;
        }

        // The existing connection is inbound, the new one is outbound and the ip addresses
        // are the same. We assume that the connections are to different nodes (and therefore
        // allow the new connection) if the new connection is a manual one (because the user
        // should know better; also, functional tests use manual connections for test nodes
        // and those nodes do share the same ip address).
        new_peer_role.is_outbound_manual()
    }

    /// The number of active inbound peers (all inbound connected peers that are not in `pending_disconnects`)
    fn inbound_peer_count(&self) -> usize {
        self.peers
            .iter()
            .filter(|(peer_id, peer)| {
                !peer.peer_role.is_outbound() && !self.pending_disconnects.contains_key(peer_id)
            })
            .count()
    }

    /// Sends ping requests and disconnects peers that do not respond in time
    fn ping_check(&mut self) {
        let now = self.time_getter.get_time();
        let mut dead_peers = Vec::new();
        for (peer_id, peer) in self.peers.iter_mut() {
            // If a ping has already been sent, wait for a reply first, do not send another ping request!
            match &peer.sent_ping {
                Some(sent_ping) => {
                    let timeout_time = (sent_ping.timestamp + *self.p2p_config.ping_timeout)
                        .expect("Both times are local, so this can't happen");
                    if now >= timeout_time {
                        log::info!("Ping check: dead peer detected: {peer_id}");
                        dead_peers.push(*peer_id);
                    } else {
                        log::debug!("Ping check: slow peer detected: {peer_id}");
                    }
                }
                None => {
                    let nonce = make_pseudo_rng().gen();
                    Self::send_peer_message(
                        &mut self.peer_connectivity_handle,
                        *peer_id,
                        PeerManagerMessage::PingRequest(PingRequest { nonce }),
                    );
                    peer.sent_ping = Some(SentPing {
                        nonce,
                        timestamp: now,
                    });
                }
            }
        }

        for peer_id in dead_peers {
            self.disconnect(
                peer_id,
                PeerDisconnectionDbAction::Keep,
                Some(DisconnectionReason::PingIgnored),
                None,
            );
        }

        self.last_ping_check_time = Some(now);
    }

    fn tip_is_stale(&self) -> bool {
        let now = self.time_getter.get_time();
        let last_tip_time = self.last_chainstate_tip_block_time.unwrap_or(self.init_time);
        let time_since_last_tip = (now - last_tip_time).unwrap_or(Duration::ZERO);

        time_since_last_tip > *self.p2p_config.peer_manager_config.stale_tip_time_diff
    }

    fn heartbeat_needed(&self, is_early_heartbeat: bool) -> bool {
        let now = self.time_getter.get_time();
        let last_heartbeat_time = self.last_heartbeat_time.unwrap_or(self.init_time);

        let next_heartbeat_min_time =
            (last_heartbeat_time + HEARTBEAT_INTERVAL_MIN).expect("Cannot happen");
        let next_heartbeat_max_time =
            (last_heartbeat_time + HEARTBEAT_INTERVAL_MAX).expect("Cannot happen");

        (now >= next_heartbeat_min_time && is_early_heartbeat) || now >= next_heartbeat_max_time
    }

    /// Determine whether we need to query the dns seed.
    ///
    /// Note that we avoid querying dns seeds unless really necessary in order to reduce their
    /// influence on the network topology (which can be bad if one of the seeds is compromised).
    fn dns_seed_query_needed(&self) -> bool {
        if self.last_dns_query_time.is_none() {
            // If the peer db is empty, it makes sense to perform the first query immediately,
            // instead of waiting for DNS_SEED_QUERY_INTERVAL to pass.
            if self.peerdb.known_addresses_count() == 0 {
                return true;
            }

            // Check whether the dns query should be forced.
            if *self.p2p_config.peer_manager_config.force_dns_query_if_no_global_addresses_known {
                let have_global_addrs =
                    self.peerdb.known_addresses().any(|addr| addr.ip_addr().is_global_unicast_ip());

                if !have_global_addrs {
                    return true;
                }
            }
        }

        let last_time = self.last_dns_query_time.unwrap_or(self.init_time);

        let now = self.time_getter.get_time();
        let next_time = (last_time + DNS_SEED_QUERY_INTERVAL).expect("Cannot happen");

        // Query the dns seed if some time has passed, but we still don't have peers
        // or if the tip is stale.
        now >= next_time
            && self.pending_outbound_connects.is_empty()
            && (self.peers.is_empty() || self.tip_is_stale())
    }

    fn ping_check_needed(&self) -> bool {
        let ping_check_enabled = !self.p2p_config.ping_check_period.is_zero();

        if ping_check_enabled {
            let now = self.time_getter.get_time();
            let last_time = self.last_ping_check_time.unwrap_or(self.init_time);
            let next_time =
                (last_time + *self.p2p_config.ping_check_period).expect("Cannot happen");

            now >= next_time
        } else {
            false
        }
    }

    /// Return true if we need to load predefined addresses into peerdb.
    fn need_load_predefined_addresses(&self) -> bool {
        if self.chain_config.predefined_peer_addresses().is_empty() {
            return false;
        }

        // Predefined addressed are only loaded after we've queried the dns seed.
        if self.last_dns_query_time.is_none() {
            return false;
        }

        // Before iterating the entire peerdb looking for a reachable address, first check if
        // we have peers (if we have a peer, we have a reachable address).
        if !(self.pending_outbound_connects.is_empty() && self.peers.is_empty()) {
            return false;
        }

        // Now check if we have a potentially reachable address. If not, the predefined addresses
        // should be loaded.
        // Note: the check for reachability is a protection against a misconfigured dns seed,
        // which may return bogus addresses.
        let peerdb_has_no_reachable_addresses = self.peerdb.reachable_addresses().next().is_none();

        peerdb_has_no_reachable_addresses
    }

    fn load_predefined_addresses(&mut self) {
        log::info!("Loading predefined peer addresses");

        for addr in self.chain_config.predefined_peer_addresses() {
            self.peerdb.peer_discovered(SocketAddress::new(*addr));
        }
    }

    fn enable_networking(&mut self, enable: bool) -> crate::Result<()> {
        if self.networking_enabled == enable {
            return Ok(());
        }

        self.networking_enabled = enable;

        if self.networking_enabled {
            log::info!("Networking is enabled");
        } else {
            log::warn!("Networking is disabled");
        }

        self.peer_connectivity_handle.enable_networking(enable)?;

        if self.networking_enabled {
            // Perform a heartbeat immediately
            self.heartbeat();
        }

        Ok(())
    }

    /// Runs the `PeerManager` event loop.
    ///
    /// The event loop has these main responsibilities:
    /// - listening to and handling control events from [`crate::sync::SyncManager`]/RPC
    /// - listening to network events
    /// - updating internal state
    /// - sending and checking ping requests
    ///
    /// After handling an event from one of the aforementioned sources, the event loop
    /// handles the error (if any) and runs the [`PeerManager::heartbeat()`] function
    /// to perform the peer manager maintenance. If the `PeerManager` doesn't receive any events,
    /// [`HEARTBEAT_INTERVAL_MIN`] and [`HEARTBEAT_INTERVAL_MAX`] defines how
    /// often the heartbeat function is called.
    /// This is done to prevent the `PeerManager` from stalling in case the network doesn't
    /// have any events.
    ///
    /// `loop_started_sender` is a helper channel for unit testing (it notifies when it's safe to change the time with `time_getter`).
    async fn run_internal(
        &mut self,
        loop_started_sender: Option<oneshot_nofail::Sender<()>>,
    ) -> crate::Result<Never> {
        if self.networking_enabled {
            let anchor_peers = self.peerdb.anchors().clone();
            if anchor_peers.is_empty() {
                // Run heartbeat immediately to start outbound connections, but only if there are no stored anchor peers.
                self.heartbeat();
            } else {
                // Skip heartbeat to give the stored anchor peers more time to connect to prevent churn!
                // The stored anchor peers should be the first connected block relay peers.
                for anchor_address in anchor_peers {
                    log::debug!("Try to connect to anchor peer {anchor_address}");
                    // The first peers should become anchor peers
                    self.connect(
                        anchor_address,
                        OutboundConnectType::Automatic {
                            block_relay_only: true,
                        },
                    );
                }
            }
        } else {
            log::warn!("Starting with networking disabled");
        }

        let mut last_time = self.time_getter.get_time();
        let mut next_time_resend_own_address = self.time_getter.get_time();

        // If true, the next heartbeat will be an "early one" (i.e. it will be triggered once
        // the "min" heartbeat interval has elapsed rather than the "max").
        let mut early_heartbeat_needed = false;

        let mut periodic_interval =
            tokio::time::interval(*self.p2p_config.peer_manager_config.main_loop_tick_interval);

        if let Some(chan) = loop_started_sender {
            chan.send(());
        }

        loop {
            tokio::select! {
                event_res = self.peer_mgr_event_receiver.recv() => {
                    self.handle_control_event(event_res.ok_or(P2pError::ChannelClosed)?);
                    early_heartbeat_needed = true;
                }

                event_res = self.peer_connectivity_handle.poll_next() => {
                    self.handle_connectivity_event(event_res?);
                    early_heartbeat_needed = true;
                },

                _ = periodic_interval.tick() => {}
            }

            // Changing the clock time can cause various problems, log such events to make it easier to find the source of the problems
            let now = self.time_getter.get_time();
            if now < last_time {
                log::warn!(
                    "Backward time adjustment detected ({} seconds)",
                    (last_time - now).unwrap_or_default().as_secs_f64()
                );
            } else if now
                > (last_time + Duration::from_secs(60)).expect("All from local clock; cannot fail")
            {
                log::warn!(
                    "Forward time jump detected ({} seconds)",
                    (now - last_time).unwrap_or_default().as_secs_f64()
                );
            }
            last_time = now;

            if self.networking_enabled && self.tip_is_stale() {
                early_heartbeat_needed = true;
            }

            // Periodic heartbeat call where new outbound connections are made
            if self.heartbeat_needed(early_heartbeat_needed) {
                self.heartbeat();
                early_heartbeat_needed = false;
            }

            if self.networking_enabled {
                // Query dns seed
                if self.dns_seed_query_needed() {
                    self.query_dns_seed().await;
                    early_heartbeat_needed = true;
                }

                if self.need_load_predefined_addresses() {
                    self.load_predefined_addresses();
                    early_heartbeat_needed = true;
                }

                // Send ping requests and disconnect dead peers
                if self.ping_check_needed() {
                    self.ping_check();
                }

                // Advertise local address regularly
                while next_time_resend_own_address <= now {
                    self.resend_own_address_randomly();

                    // Pick a random outbound peer to resend the listening address to.
                    // The delay has this value because normally there are at most
                    // `outbound_full_relay_count` peers that can have `discovered_own_address`.
                    // Note that in tests `outbound_full_relay_count` may be zero, so we have to
                    // adjust it for this case.
                    let delay_divisor = std::cmp::max(
                        *self.p2p_config.peer_manager_config.outbound_full_relay_count,
                        1,
                    );
                    let delay = (RESEND_OWN_ADDRESS_TO_PEER_PERIOD / delay_divisor as u32)
                        .mul_f64(utils::exp_rand::exponential_rand(&mut make_pseudo_rng()));
                    next_time_resend_own_address = (next_time_resend_own_address + delay)
                        .expect("Time derived from local clock; cannot fail");
                }
            }
        }
    }

    pub async fn run(mut self) -> crate::Result<Never> {
        self.run_internal(None).await
    }

    // A variant of 'run' to use in tests.
    #[cfg(test)]
    pub async fn run_without_consuming_self(&mut self) -> crate::Result<Never> {
        self.run_internal(None).await
    }

    #[cfg(test)]
    pub fn peerdb(&self) -> &peerdb::PeerDb<S> {
        &self.peerdb
    }
}

pub trait Observer {
    fn on_peer_ban_score_adjustment(&mut self, address: SocketAddress, new_score: u32);
    fn on_peer_ban(&mut self, address: BannableAddress);
    fn on_peer_discouragement(&mut self, address: BannableAddress);
    // This will be called at the end of "heartbeat" function.
    fn on_heartbeat(&mut self);
    // This will be called for both incoming and outgoing connections.
    fn on_connection_accepted(&mut self, address: SocketAddress, peer_role: PeerRole);
}

pub trait PeerManagerInterface {
    #[cfg(test)]
    fn peers(&self) -> &BTreeMap<PeerId, PeerContext>;

    #[cfg(test)]
    fn pending_outbound_conn_addrs(&self) -> Vec<SocketAddress>;

    #[cfg(test)]
    fn peer_db(&self) -> &dyn peerdb::PeerDbInterface;

    #[cfg(test)]
    fn peer_db_mut(&mut self) -> &mut dyn peerdb::PeerDbInterface;
}

impl<T, S> PeerManagerInterface for PeerManager<T, S>
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    S: PeerDbStorage,
{
    #[cfg(test)]
    fn peers(&self) -> &BTreeMap<PeerId, PeerContext> {
        &self.peers
    }

    #[cfg(test)]
    fn pending_outbound_conn_addrs(&self) -> Vec<SocketAddress> {
        self.pending_outbound_connects.keys().copied().collect()
    }

    #[cfg(test)]
    fn peer_db(&self) -> &dyn peerdb::PeerDbInterface {
        &self.peerdb
    }

    #[cfg(test)]
    fn peer_db_mut(&mut self) -> &mut dyn peerdb::PeerDbInterface {
        &mut self.peerdb
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub mod test_utils {
    pub use super::tests::utils::*;
}
