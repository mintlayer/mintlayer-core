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

pub mod address_groups;
pub mod dns_seed;
pub mod peer_context;
pub mod peerdb;
pub mod peerdb_common;
pub mod peers_eviction;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
    time::Duration,
};

use futures::never::Never;
use p2p_types::{
    bannable_address::BannableAddress, ip_or_socket_address::IpOrSocketAddress,
    socket_address::SocketAddress,
};
use tokio::sync::mpsc;

use chainstate::ban_score::BanScore;
use common::{
    chain::ChainConfig,
    primitives::time::{duration_to_int, Time},
    time_getter::TimeGetter,
};
use crypto::random::{make_pseudo_rng, seq::IteratorRandom, Rng};
use logging::log;
use utils::{
    bloom_filters::rolling_bloom_filter::RollingBloomFilter, ensure, make_config_setting,
    set_flag::SetFlag,
};

use crate::{
    config::P2pConfig,
    error::{P2pError, PeerError, ProtocolError},
    interface::types::ConnectedPeer,
    message::{
        AddrListRequest, AddrListResponse, AnnounceAddrRequest, PeerManagerMessage, PingRequest,
        PingResponse,
    },
    net::{
        types::{
            services::{Service, Services},
            ConnectivityEvent,
        },
        types::{PeerInfo, PeerRole, Role},
        ConnectivityService, NetworkingService,
    },
    peer_manager_event::PeerDisconnectionDbAction,
    types::{
        peer_address::{PeerAddress, PeerAddressIp4, PeerAddressIp6},
        peer_id::PeerId,
    },
    utils::{oneshot_nofail, rate_limiter::RateLimiter},
    PeerManagerEvent,
};

use self::{
    address_groups::AddressGroup,
    dns_seed::{DefaultDnsSeed, DnsSeed},
    peer_context::{PeerContext, SentPing},
    peerdb::storage::PeerDbStorage,
    peers_eviction::{
        OutboundBlockRelayConnectionMinAge, OutboundFullRelayConnectionMinAge,
        PreservedInboundCountAddressGroup, PreservedInboundCountNewBlocks,
        PreservedInboundCountNewTransactions, PreservedInboundCountPing,
    },
};

#[derive(Default, Debug)]
pub struct PeerManagerConfig {
    /// Maximum allowed number of inbound connections.
    pub max_inbound_connections: MaxInboundConnections,

    /// The number of inbound peers to preserve based on the address group.
    pub preserved_inbound_count_address_group: PreservedInboundCountAddressGroup,
    /// The number of inbound peers to preserve based on ping.
    pub preserved_inbound_count_ping: PreservedInboundCountPing,
    /// The number of inbound peers to preserve based on the last time they sent us new blocks.
    pub preserved_inbound_count_new_blocks: PreservedInboundCountNewBlocks,
    /// The number of inbound peers to preserve based on the last time they sent us new transactions.
    pub preserved_inbound_count_new_transactions: PreservedInboundCountNewTransactions,

    /// The desired maximum number of full relay outbound connections.
    /// Note that this limit may be exceeded temporarily by up to outbound_full_relay_extra_count
    /// connections.
    pub outbound_full_relay_count: OutboundFullRelayCount,
    /// The number of extra full relay connections that we may establish when a stale tip
    /// is detected.
    pub outbound_full_relay_extra_count: OutboundFullRelayExtraCount,

    /// The desired maximum number of block relay outbound connections.
    /// Note that this limit may be exceeded temporarily by up to outbound_block_relay_extra_count
    /// connections.
    pub outbound_block_relay_count: OutboundBlockRelayCount,
    /// The number of extra block relay connections that we will establish and evict regularly.
    pub outbound_block_relay_extra_count: OutboundBlockRelayExtraCount,

    /// Outbound block relay connections younger than this age will not be taken into account
    /// during eviction.
    /// Note that extra block relay connections are established and evicted on a regular basis
    /// during normal operation. So, this interval basically determines how often those extra
    /// connections will come and go.
    pub outbound_block_relay_connection_min_age: OutboundBlockRelayConnectionMinAge,
    /// Outbound full relay connections younger than this age will not be taken into account
    /// during eviction.
    /// Note that extra full relay connections are established if the current tip becomes stale.
    pub outbound_full_relay_connection_min_age: OutboundFullRelayConnectionMinAge,

    /// The time after which the tip will be considered stale.
    pub stale_tip_time_diff: StaleTipTimeDiff,

    /// How often the main loop should be woken up when no other events occur.
    pub main_loop_tick_interval: MainLoopTickInterval,
}

impl PeerManagerConfig {
    pub fn total_preserved_inbound_count(&self) -> usize {
        *self.preserved_inbound_count_address_group
            + *self.preserved_inbound_count_ping
            + *self.preserved_inbound_count_new_blocks
            + *self.preserved_inbound_count_new_transactions
    }

    /// The desired maximum number of automatic outbound connections.
    pub fn outbound_full_and_block_relay_count(&self) -> usize {
        *self.outbound_full_relay_count + *self.outbound_block_relay_count
    }
}

make_config_setting!(MaxInboundConnections, usize, 128);
make_config_setting!(OutboundFullRelayCount, usize, 8);
make_config_setting!(OutboundFullRelayExtraCount, usize, 1);
make_config_setting!(OutboundBlockRelayCount, usize, 2);
make_config_setting!(OutboundBlockRelayExtraCount, usize, 1);
make_config_setting!(StaleTipTimeDiff, Duration, Duration::from_secs(30 * 60));
make_config_setting!(MainLoopTickInterval, Duration, Duration::from_secs(1));

/// Lower bound for how often [`PeerManager::heartbeat()`] is called
pub const PEER_MGR_HEARTBEAT_INTERVAL_MIN: Duration = Duration::from_secs(5);
/// Upper bound for how often [`PeerManager::heartbeat()`] is called
pub const PEER_MGR_HEARTBEAT_INTERVAL_MAX: Duration = Duration::from_secs(30);

/// How often resend own address to a specific peer (on average)
const RESEND_OWN_ADDRESS_TO_PEER_PERIOD: Duration = Duration::from_secs(24 * 60 * 60);

/// The interval at which to contact DNS seed servers.
pub const PEER_MGR_DNS_RELOAD_INTERVAL: Duration = Duration::from_secs(60);

/// How many addresses are allowed to be sent
const MAX_ADDRESS_COUNT: usize = 1000;

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
}

impl OutboundConnectType {
    fn block_relay_only(&self) -> bool {
        match self {
            OutboundConnectType::Automatic { block_relay_only } => *block_relay_only,
            OutboundConnectType::Reserved | OutboundConnectType::Manual { response_sender: _ } => {
                false
            }
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
    /// If true, we've already loaded the predefined addresses into peerdb.
    predefined_addresses_already_loaded: bool,
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
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        handle: T::ConnectivityHandle,
        peer_mgr_event_receiver: mpsc::UnboundedReceiver<PeerManagerEvent>,
        time_getter: TimeGetter,
        peerdb_storage: S,
    ) -> crate::Result<Self> {
        Self::new_generic(
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
        let now = time_getter.get_time();
        assert!(!p2p_config.outbound_connection_timeout.is_zero());
        assert!(!p2p_config.ping_timeout.is_zero());
        Ok(PeerManager {
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
            observer,
            dns_seed,
            init_time: now,
            last_chainstate_tip_block_time: None,
            last_heartbeat_time: None,
            last_dns_query_time: None,
            last_ping_check_time: None,
            predefined_addresses_already_loaded: false,
        })
    }

    /// Verify that the peer address has a public routable IP and any valid (non-zero) port.
    /// Private and local IPs are allowed if `allow_discover_private_ips` is true.
    fn is_peer_address_valid(&self, address: &PeerAddress) -> bool {
        SocketAddress::from_peer_address(address, *self.p2p_config.allow_discover_private_ips)
            .is_some()
    }

    /// Discover public addresses for this node after a new outbound connection is made
    ///
    /// *receiver_address* is this host socket address as seen and reported by remote peer.
    /// This should work for hosts with public IPs and for hosts behind NAT with port forwarding (same port is assumed).
    /// This won't work for majority of nodes but that should be accepted.
    fn discover_own_address(
        &mut self,
        peer_role: PeerRole,
        common_services: Services,
        receiver_address: Option<PeerAddress>,
    ) -> Option<SocketAddress> {
        let discover = match peer_role {
            PeerRole::Inbound | PeerRole::OutboundBlockRelay => false,
            PeerRole::OutboundFullRelay | PeerRole::OutboundManual => {
                common_services.has_service(Service::PeerAddresses)
            }
        };
        if !discover {
            return None;
        }

        let receiver_address = receiver_address?;

        // Take IP and use port numbers from all listening sockets (with same IP version)
        let discovered_own_addresses = self
            .peer_connectivity_handle
            .local_addresses()
            .iter()
            .map(SocketAddress::as_peer_address)
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
                SocketAddress::from_peer_address(
                    &address,
                    *self.p2p_config.allow_discover_private_ips,
                )
            })
            .collect::<Vec<_>>();

        // Send only one address because of the rate limiter (see `ADDR_RATE_INITIAL_SIZE`).
        // Select a random address to give all addresses a chance to be discovered by the network.
        discovered_own_addresses.into_iter().choose(&mut make_pseudo_rng())
    }

    /// Send address announcement to the selected peer (if the address is new)
    /// `peer_id` must be from the connected peer.
    fn announce_address(&mut self, peer_id: PeerId, address: SocketAddress) {
        let peer = self.peers.get_mut(&peer_id).expect("peer must be known");
        if !peer.announced_addresses.contains(&address) {
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

    fn is_whitelisted_node(peer_role: PeerRole) -> bool {
        match peer_role {
            PeerRole::Inbound | PeerRole::OutboundFullRelay | PeerRole::OutboundBlockRelay => {
                // TODO: Add whitelisted IPs option and check it here
                false
            }
            PeerRole::OutboundManual => true,
        }
    }

    /// Adjust peer score
    ///
    /// If the peer is known, update its existing peer score and report
    /// if it should be disconnected when score reached the threshold.
    /// Unknown peers are reported as to be disconnected.
    ///
    /// If peer is banned, it is removed from the connected peers
    /// and its address is marked as banned.
    fn adjust_peer_score(&mut self, peer_id: PeerId, score: u32) {
        let peer = match self.peers.get_mut(&peer_id) {
            Some(peer) => peer,
            None => return,
        };

        if Self::is_whitelisted_node(peer.peer_role) {
            log::info!(
                "Not adjusting peer score for the whitelisted peer {peer_id}, adjustment {score}",
            );
            return;
        }

        peer.score = peer.score.saturating_add(score);

        log::info!(
            "Adjusting peer score for peer {peer_id}, adjustment {score}, new score {}",
            peer.score
        );

        if let Some(o) = self.observer.as_mut() {
            o.on_peer_ban_score_adjustment(peer.address, peer.score)
        }

        if peer.score >= *self.p2p_config.ban_threshold {
            let address = peer.address.as_bannable();
            self.ban(address);
        }
    }

    /// Adjust peer score after a failed handshake.
    ///
    /// Note that currently intermediate scores are not stored in the peer db, so this call will
    /// only make any effect if the passed score is bigger than the ban threshold.
    fn adjust_peer_score_on_failed_handshake(&mut self, peer_address: SocketAddress, score: u32) {
        let whitelisted_node =
            self.pending_outbound_connects
                .get(&peer_address)
                .map_or(false, |pending_connect| {
                    Self::is_whitelisted_node(Self::determine_outbound_peer_role(pending_connect))
                });
        if whitelisted_node {
            log::info!(
                "Not adjusting peer score for the whitelisted peer at address {peer_address}, adjustment {score}",
            );
            return;
        }

        if let Some(o) = self.observer.as_mut() {
            o.on_peer_ban_score_adjustment(peer_address, score);
        }

        if score >= *self.p2p_config.ban_threshold {
            let address = peer_address.as_bannable();
            self.ban(address);
        }
    }

    fn ban(&mut self, address: BannableAddress) {
        let to_disconnect = self
            .peers
            .values()
            .filter_map(|peer| {
                if peer.address.as_bannable() == address {
                    Some(peer.info.peer_id)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        log::info!("Ban {:?}, disconnect peers: {:?}", address, to_disconnect);

        self.peerdb.ban(address);

        if let Some(o) = self.observer.as_mut() {
            o.on_peer_ban(address);
        }

        for peer_id in to_disconnect {
            self.disconnect(peer_id, PeerDisconnectionDbAction::Keep, None);
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
    ) -> crate::Result<()> {
        ensure!(
            !self.pending_outbound_connects.contains_key(&address),
            P2pError::PeerError(PeerError::Pending(address.to_string())),
        );
        ensure!(
            !self.is_address_connected(&address),
            P2pError::PeerError(PeerError::PeerAlreadyExists),
        );

        let bannable_address = address.as_bannable();
        ensure!(
            !self.peerdb.is_address_banned(&bannable_address)
                || self.peerdb.is_reserved_node(&address),
            P2pError::PeerError(PeerError::BannedAddress(address.to_string())),
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

        log::debug!("try a new outbound connection, address: {address:?}, local_services_override: {local_services_override:?}, block_relay_only: {block_relay_only:?}");
        let res = self.try_connect(address, local_services_override);

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
                log::debug!("outbound connection to {address:?} failed: {e}");
                match outbound_connect_type {
                    OutboundConnectType::Automatic {
                        block_relay_only: _,
                    }
                    | OutboundConnectType::Reserved => {}
                    OutboundConnectType::Manual { response_sender } => {
                        response_sender.send(Err(e));
                    }
                }
            }
        }
    }

    // Try to disconnect a connected peer
    fn try_disconnect(&mut self, peer_id: PeerId) -> crate::Result<()> {
        ensure!(
            !self.pending_disconnects.contains_key(&peer_id),
            P2pError::PeerError(PeerError::Pending(peer_id.to_string())),
        );

        ensure!(
            self.peers.contains_key(&peer_id),
            P2pError::PeerError(PeerError::PeerDoesntExist),
        );

        self.peer_connectivity_handle.disconnect(peer_id)?;

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
        response_sender: Option<oneshot_nofail::Sender<crate::Result<()>>>,
    ) {
        log::debug!("disconnect peer {peer_id}");
        let res = self.try_disconnect(peer_id);

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
                log::debug!("disconnecting new peer {peer_id} failed: {e}");
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
            info.is_compatible(&self.chain_config),
            P2pError::ProtocolError(ProtocolError::DifferentNetwork(
                *self.chain_config.magic_bytes(),
                info.network,
            ))
        );
        ensure!(
            !self.is_peer_connected(info.peer_id),
            P2pError::PeerError(PeerError::PeerAlreadyExists),
        );
        ensure!(
            !self.is_address_connected(address),
            P2pError::PeerError(PeerError::PeerAlreadyExists),
        );
        ensure!(
            !self.peerdb.is_address_banned(&address.as_bannable()),
            P2pError::PeerError(PeerError::BannedAddress(address.to_string())),
        );
        ensure!(
            !info.common_services.is_empty(),
            P2pError::PeerError(PeerError::EmptyServices),
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
                    && !self.try_evict_random_inbound_connection()
                {
                    log::info!("no peer is selected for eviction, new connection is dropped");
                    return Err(P2pError::PeerError(PeerError::TooManyPeers));
                }
            }

            PeerRole::OutboundManual => {}

            PeerRole::OutboundFullRelay => {
                let expected: Services = (*self.p2p_config.node_type).into();
                utils::ensure!(
                    info.common_services == expected,
                    P2pError::PeerError(PeerError::UnexpectedServices {
                        expected_services: expected,
                        available_services: info.common_services,
                    })
                );
            }

            PeerRole::OutboundBlockRelay => {
                let expected: Services = [Service::Blocks].as_slice().into();
                utils::ensure!(
                    info.common_services == expected,
                    P2pError::PeerError(PeerError::UnexpectedServices {
                        expected_services: expected,
                        available_services: info.common_services,
                    })
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
                peers_eviction::EvictionCandidate::new(peer, &self.peer_eviction_random_state, now)
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
        ) {
            log::info!("inbound peer {peer_id} is selected for eviction");
            self.disconnect(peer_id, PeerDisconnectionDbAction::Keep, None);
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
        ) {
            log::info!("block relay peer {peer_id} is selected for eviction");
            self.disconnect(peer_id, PeerDisconnectionDbAction::Keep, None);
        }
    }

    /// If there are too many outbound full relay peers, find and disconnect the "worst" one.
    fn evict_full_relay_peer(&mut self) {
        if let Some(peer_id) = peers_eviction::select_for_eviction_full_relay(
            self.eviction_candidates(PeerRole::OutboundFullRelay),
            &self.p2p_config.peer_manager_config,
        ) {
            log::info!("full relay peer {peer_id} is selected for eviction");
            self.disconnect(peer_id, PeerDisconnectionDbAction::Keep, None);
        }
    }

    /// Should we load addresses from this peer?
    fn should_load_addresses_from(peer_role: PeerRole) -> bool {
        // Load addresses only from outbound peers, like it's done in Bitcoin Core
        match peer_role {
            PeerRole::OutboundFullRelay | PeerRole::OutboundManual => true,
            PeerRole::Inbound | PeerRole::OutboundBlockRelay => false,
        }
    }

    /// Should we send addresses to this peer if it requests them?
    fn should_send_addresses_to(peer_role: PeerRole) -> bool {
        // Send addresses only to inbound peers, like it's done in Bitcoin Core
        match peer_role {
            PeerRole::Inbound => true,
            PeerRole::OutboundFullRelay
            | PeerRole::OutboundBlockRelay
            | PeerRole::OutboundManual => false,
        }
    }

    /// Try accept new connection
    ///
    /// The event is received from the networking backend and it's either a result of an incoming
    /// connection from a remote peer or a response to an outbound connection that was initiated
    /// by the node as result of the peer manager maintenance.
    fn try_accept_connection(
        &mut self,
        address: SocketAddress,
        peer_role: PeerRole,
        info: PeerInfo,
        receiver_address: Option<PeerAddress>,
    ) -> crate::Result<()> {
        let peer_id = info.peer_id;

        self.validate_connection(&address, peer_role, &info)?;

        self.peer_connectivity_handle.accept(peer_id)?;

        log::info!(
            "new peer accepted, peer_id: {peer_id}, address: {address:?}, role: {peer_role:?}, protocol_version: {:?}",
            info.protocol_version
        );

        if info.common_services.has_service(Service::PeerAddresses) {
            self.subscribed_to_peer_addresses.insert(info.peer_id);
        }

        if Self::should_load_addresses_from(peer_role) {
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

        let discovered_own_address =
            self.discover_own_address(peer_role, info.common_services, receiver_address);

        let peer = PeerContext {
            created_at: self.time_getter.get_time(),
            info,
            address,
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
        };

        Self::send_own_address_to_peer(&mut self.peer_connectivity_handle, &peer);

        let old_value = self.peers.insert(peer_id, peer);
        assert!(old_value.is_none());

        match peer_role {
            PeerRole::Inbound => {}
            PeerRole::OutboundFullRelay
            | PeerRole::OutboundBlockRelay
            | PeerRole::OutboundManual => {
                self.peerdb.outbound_peer_connected(address);
            }
        }

        if peer_role == PeerRole::OutboundBlockRelay {
            let anchor_addresses = self
                .peers
                .values()
                .filter_map(|peer| match peer.peer_role {
                    PeerRole::Inbound | PeerRole::OutboundFullRelay | PeerRole::OutboundManual => {
                        None
                    }
                    PeerRole::OutboundBlockRelay => Some(peer.address),
                })
                // Note: there may be more than outbound_block_relay_count block relay connections
                // at a given moment, but the extra ones will soon be evicted. Since connections
                // with smaller peer ids are less likely to be evicted, we choose them here.
                .take(*self.p2p_config.peer_manager_config.outbound_block_relay_count)
                .collect();
            self.peerdb.set_anchors(anchor_addresses);
        }

        if let Some(o) = self.observer.as_mut() {
            o.on_connection_accepted(address, peer_role)
        }

        Ok(())
    }

    fn determine_outbound_peer_role(pending_connect: &PendingConnect) -> PeerRole {
        match pending_connect.outbound_connect_type {
            OutboundConnectType::Automatic { block_relay_only } => {
                if block_relay_only {
                    PeerRole::OutboundBlockRelay
                } else {
                    PeerRole::OutboundFullRelay
                }
            }
            OutboundConnectType::Reserved => PeerRole::OutboundManual,
            OutboundConnectType::Manual { response_sender: _ } => PeerRole::OutboundManual,
        }
    }

    fn accept_connection(
        &mut self,
        address: SocketAddress,
        role: Role,
        info: PeerInfo,
        receiver_address: Option<PeerAddress>,
    ) {
        let peer_id = info.peer_id;

        let (peer_role, response) = match role {
            Role::Inbound => (PeerRole::Inbound, None),
            Role::Outbound => {
                let pending_connect = self.pending_outbound_connects.remove(&address).expect(
                    "the address must be present in pending_outbound_connects (accept_connection)",
                );
                let role = Self::determine_outbound_peer_role(&pending_connect);
                let response_sender = match pending_connect.outbound_connect_type {
                    OutboundConnectType::Automatic {
                        block_relay_only: _,
                    }
                    | OutboundConnectType::Reserved => None,
                    OutboundConnectType::Manual { response_sender } => Some(response_sender),
                };

                (role, response_sender)
            }
        };

        let accept_res = self.try_accept_connection(address, peer_role, info, receiver_address);

        if let Err(accept_err) = &accept_res {
            log::debug!("connection rejected for peer {peer_id}: {accept_err}");

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
            let disconnect_result = self.peer_connectivity_handle.disconnect(peer_id);
            if let Err(err) = disconnect_result {
                log::error!("disconnect failed unexpectedly: {err:?}");
            }

            match peer_role {
                PeerRole::Inbound => {}
                PeerRole::OutboundFullRelay
                | PeerRole::OutboundBlockRelay
                | PeerRole::OutboundManual => {
                    self.peerdb.report_outbound_failure(address, accept_err);
                }
            }
        }

        if let Some(response) = response {
            response.send(accept_res);
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
        self.peerdb.report_outbound_failure(address, &error);

        let PendingConnect {
            outbound_connect_type,
        } = self.pending_outbound_connects.remove(&address).expect(
            "the address must be present in pending_outbound_connects (handle_outbound_error)",
        );
        match outbound_connect_type {
            OutboundConnectType::Automatic {
                block_relay_only: _,
            }
            | OutboundConnectType::Reserved => {}
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
                "peer disconnected, peer_id: {}, address: {:?}",
                peer.info.peer_id,
                peer.address
            );

            match peer.peer_role {
                PeerRole::Inbound => {}
                PeerRole::OutboundFullRelay
                | PeerRole::OutboundBlockRelay
                | PeerRole::OutboundManual => {
                    self.peerdb.outbound_peer_disconnected(peer.address);
                }
            }

            if let Some(PendingDisconnect {
                peerdb_action,
                response_sender,
            }) = self.pending_disconnects.remove(&peer_id)
            {
                match peerdb_action {
                    PeerDisconnectionDbAction::Keep => {}
                    PeerDisconnectionDbAction::RemoveIfOutbound => match peer.peer_role {
                        PeerRole::Inbound => {}
                        PeerRole::OutboundFullRelay
                        | PeerRole::OutboundBlockRelay
                        | PeerRole::OutboundManual => {
                            self.peerdb.remove_outbound_address(&peer.address);
                        }
                    },
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
        log::debug!("Dns seed queried, addresses = {addresses:?}");
        for addr in addresses {
            self.peerdb.peer_discovered(addr);
        }

        self.last_dns_query_time = Some(self.time_getter.get_time());
    }

    fn peer_addresses_iter(&self) -> impl Iterator<Item = (SocketAddress, PeerRole)> + '_ {
        let pending_automatic_outbound =
            self.pending_outbound_connects.iter().map(|(addr, pending_conn)| {
                let role = Self::determine_outbound_peer_role(pending_conn);
                (*addr, role)
            });
        let connected_automatic_outbound =
            self.peers.values().map(|peer_ctx| (peer_ctx.address, peer_ctx.peer_role));
        connected_automatic_outbound.chain(pending_automatic_outbound)
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
    /// TODO: IP address diversity check?
    /// TODO: exploratory peer connections?
    /// TODO: close connection with low-score peers in favor of peers with higher score?
    ///
    /// The process starts by first checking if the number of active connections is less than
    /// the number of desired connections and there are available peers, the function tries to
    /// establish new connections. After that it updates the peer scores and discards any records
    /// that no longer need to be stored.
    fn heartbeat(&mut self) {
        // Expired banned addresses are dropped here, keep this call!
        self.peerdb.heartbeat();

        self.establish_new_connections();

        self.evict_block_relay_peer();
        self.evict_full_relay_peer();

        self.last_heartbeat_time = Some(self.time_getter.get_time());

        if let Some(o) = self.observer.as_mut() {
            o.on_heartbeat();
        }
    }

    fn establish_new_connections(&mut self) {
        let mut cur_outbound_full_relay_conn_count = 0;
        let mut cur_outbound_block_relay_conn_count = 0;
        let mut cur_outbound_conn_addr_groups = BTreeSet::new();
        for (addr, role) in self.peer_addresses_iter() {
            let addr_group = AddressGroup::from_peer_address(&addr.as_peer_address());

            match role {
                PeerRole::Inbound => {}
                PeerRole::OutboundManual => {
                    // TODO: should we include manual peer connection in cur_outbound_conn_addr_groups,
                    // in order to avoid opening new automatic connections to their address groups?
                    // (Bitcoin does it).
                    // See the TODO section of https://github.com/mintlayer/mintlayer-core/issues/832
                    // Note that this change will require adjusting expected connections numbers
                    // in the "discovered_node" tests.
                }
                PeerRole::OutboundFullRelay => {
                    cur_outbound_full_relay_conn_count += 1;
                    cur_outbound_conn_addr_groups.insert(addr_group);
                }
                PeerRole::OutboundBlockRelay => {
                    cur_outbound_block_relay_conn_count += 1;
                    cur_outbound_conn_addr_groups.insert(addr_group);
                }
            }
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

        let new_full_relay_conn_addresses = self.peerdb.select_new_non_reserved_outbound_addresses(
            &cur_outbound_conn_addr_groups,
            needed_outbound_full_relay_conn_count,
        );

        // TODO: in bitcoin they also try to create an extra outbound full relay connection
        // to an address in a reachable network in which there are no outbound full relay or
        // manual connections (see CConnman::MaybePickPreferredNetwork for reference).
        // See the TODO section of https://github.com/mintlayer/mintlayer-core/issues/832

        for address in new_full_relay_conn_addresses.into_iter() {
            let addr_group = AddressGroup::from_peer_address(&address.as_peer_address());
            cur_outbound_conn_addr_groups.insert(addr_group);

            self.connect(
                address,
                OutboundConnectType::Automatic {
                    block_relay_only: false,
                },
            );
        }

        let needed_outbound_block_relay_conn_count =
            (*self.p2p_config.peer_manager_config.outbound_block_relay_count
                + *self.p2p_config.peer_manager_config.outbound_block_relay_extra_count)
                .saturating_sub(cur_outbound_block_relay_conn_count);

        let new_block_relay_conn_addresses =
            self.peerdb.select_new_non_reserved_outbound_addresses(
                &cur_outbound_conn_addr_groups,
                needed_outbound_block_relay_conn_count,
            );

        for address in new_block_relay_conn_addresses.into_iter() {
            self.connect(
                address,
                OutboundConnectType::Automatic {
                    block_relay_only: true,
                },
            );
        }

        let cur_pending_outbound_conn_addresses =
            self.pending_outbound_connects.keys().cloned().collect::<BTreeSet<_>>();
        let new_reserved_conn_addresses = self
            .peerdb
            .select_reserved_outbound_addresses(&cur_pending_outbound_conn_addresses);

        for address in new_reserved_conn_addresses.into_iter() {
            self.connect(address, OutboundConnectType::Reserved);
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
        }
    }

    fn handle_announce_addr_request(&mut self, peer_id: PeerId, address: PeerAddress) {
        if let Some(address) =
            SocketAddress::from_peer_address(&address, *self.p2p_config.allow_discover_private_ips)
        {
            let peer = self
                .peers
                .get_mut(&peer_id)
                .expect("peer sending AnnounceAddrRequest must be known");
            if !peer.address_rate_limiter.accept(self.time_getter.get_time()) {
                log::debug!("address announcement is rate limited from peer {peer_id}");
                return;
            }

            peer.announced_addresses.insert(&address, &mut make_pseudo_rng());

            self.peerdb.peer_discovered(address);

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

    fn handle_addr_list_request(&mut self, peer_id: PeerId) {
        let peer = self.peers.get_mut(&peer_id).expect("peer must be known");
        // Only one request allowed to reduce load in case of DoS attacks
        if !Self::should_send_addresses_to(peer.peer_role)
            || peer.addr_list_req_received.test_and_set()
        {
            log::warn!("Ignore unexpected address list request from peer {peer_id}");
            return;
        }

        let addresses = self
            .peerdb
            .known_addresses()
            .map(SocketAddress::as_peer_address)
            .filter(|address| self.is_peer_address_valid(address))
            .choose_multiple(&mut make_pseudo_rng(), MAX_ADDRESS_COUNT);

        assert!(addresses.len() <= MAX_ADDRESS_COUNT);

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
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(P2pError::PeerError(PeerError::PeerDoesntExist))?;
        ensure!(
            addresses.len() <= MAX_ADDRESS_COUNT,
            P2pError::ProtocolError(ProtocolError::AddressListLimitExceeded)
        );
        ensure!(
            Self::should_load_addresses_from(peer.peer_role)
                && !peer.addr_list_resp_received.test_and_set(),
            P2pError::ProtocolError(ProtocolError::UnexpectedMessage(
                "AddrListResponse".to_owned()
            ))
        );

        for address in addresses {
            if let Some(address) = SocketAddress::from_peer_address(
                &address,
                *self.p2p_config.allow_discover_private_ips,
            ) {
                self.peerdb.peer_discovered(address);
            }
        }

        Ok(())
    }

    fn handle_addr_list_response(&mut self, peer_id: PeerId, addresses: Vec<PeerAddress>) {
        let res = self.try_handle_addr_list_response(peer_id, addresses);
        if let Err(err) = res {
            log::debug!("try_handle_addr_list_response failed: {err}");
            self.adjust_peer_score(peer_id, err.ban_score());
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
                        "wrong nonce in ping response from peer {}, received: {}, expected: {}",
                        peer_id,
                        nonce,
                        sent_ping.nonce,
                    );
                }
            } else {
                log::debug!("unexpected ping response received from peer {}", peer_id);
            }
        }
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
            PeerManagerEvent::Disconnect(peer_id, peerdb_action, response_sender) => {
                self.disconnect(peer_id, peerdb_action, Some(response_sender));
            }
            PeerManagerEvent::AdjustPeerScore(peer_id, score, response_sender) => {
                log::debug!("adjust peer {peer_id} score: {score}");
                self.adjust_peer_score(peer_id, score);
                response_sender.send(Ok(()));
            }
            PeerManagerEvent::NewTipReceived { peer_id, block_id } => {
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    log::debug!("new tip {block_id} received from peer {peer_id}");
                    peer.last_tip_block_time = Some(self.time_getter.get_time());
                }
            }
            PeerManagerEvent::NewChainstateTip(block_id) => {
                log::debug!("new tip {block_id} added to chainstate");
                self.last_chainstate_tip_block_time = Some(self.time_getter.get_time());
            }
            PeerManagerEvent::NewValidTransactionReceived { peer_id, txid } => {
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    log::debug!("new transaction {txid} received from peer {peer_id}");
                    peer.last_tx_time = Some(self.time_getter.get_time());
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
            PeerManagerEvent::AddReserved(address, response_sender) => {
                let address = ip_or_socket_address_to_peer_address(&address, &self.chain_config);
                self.peerdb.add_reserved_node(address);
                // Initiate new outbound connection without waiting for `heartbeat`
                self.connect(address, OutboundConnectType::Reserved);
                response_sender.send(Ok(()));
            }
            PeerManagerEvent::RemoveReserved(address, response_sender) => {
                let address = ip_or_socket_address_to_peer_address(&address, &self.chain_config);
                self.peerdb.remove_reserved_node(address);
                response_sender.send(Ok(()));
            }
            PeerManagerEvent::ListBanned(response_sender) => {
                response_sender.send(self.peerdb.list_banned().cloned().collect())
            }
            PeerManagerEvent::Ban(address, response_sender) => {
                self.ban(address);
                response_sender.send(Ok(()));
            }
            PeerManagerEvent::Unban(address, response_sender) => {
                self.peerdb.unban(&address);
                response_sender.send(Ok(()));
            }
            PeerManagerEvent::GenericQuery(query_func) => {
                query_func(self);
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
                address,
                peer_info,
                receiver_address,
            } => {
                self.accept_connection(address, Role::Inbound, peer_info, receiver_address);
            }
            ConnectivityEvent::OutboundAccepted {
                address,
                peer_info,
                receiver_address,
            } => {
                self.accept_connection(address, Role::Outbound, peer_info, receiver_address);
            }
            ConnectivityEvent::ConnectionClosed { peer_id } => {
                self.connection_closed(peer_id);
            }
            ConnectivityEvent::ConnectionError { address, error } => {
                self.handle_outbound_error(address, error);
            }
            ConnectivityEvent::Misbehaved { peer_id, error } => {
                self.adjust_peer_score(peer_id, error.ban_score());
            }
            ConnectivityEvent::MisbehavedOnHandshake { address, error } => {
                self.adjust_peer_score_on_failed_handshake(address, error.ban_score());
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
                address: context.address,
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
            })
            .collect()
    }

    /// Checks if the peer is in active state
    fn is_peer_connected(&self, peer_id: PeerId) -> bool {
        self.peers.get(&peer_id).is_some()
    }

    fn is_address_connected(&self, address: &SocketAddress) -> bool {
        self.peers.values().any(|peer| peer.address == *address)
    }

    /// The number of active inbound peers (all inbound connected peers that are not in `pending_disconnects`)
    fn inbound_peer_count(&self) -> usize {
        self.peers
            .iter()
            .filter(|(peer_id, peer)| match peer.peer_role {
                PeerRole::Inbound => !self.pending_disconnects.contains_key(peer_id),
                PeerRole::OutboundFullRelay
                | PeerRole::OutboundBlockRelay
                | PeerRole::OutboundManual => false,
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
                        log::info!("ping check: dead peer detected: {peer_id}");
                        dead_peers.push(*peer_id);
                    } else {
                        log::debug!("ping check: slow peer detected: {peer_id}");
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
            self.disconnect(peer_id, PeerDisconnectionDbAction::Keep, None);
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
            (last_heartbeat_time + PEER_MGR_HEARTBEAT_INTERVAL_MIN).expect("Cannot happen");
        let next_heartbeat_max_time =
            (last_heartbeat_time + PEER_MGR_HEARTBEAT_INTERVAL_MAX).expect("Cannot happen");

        (now >= next_heartbeat_min_time && is_early_heartbeat) || now >= next_heartbeat_max_time
    }

    // We query dns seed if there are no outbound connections, or the tip is stale, or we
    // haven't queried it at least once yet.
    fn dns_seed_query_needed(&self) -> bool {
        if let Some(last_time) = self.last_dns_query_time {
            let now = self.time_getter.get_time();
            let next_time = (last_time + PEER_MGR_DNS_RELOAD_INTERVAL).expect("Cannot happen");

            now >= next_time
                && self.pending_outbound_connects.is_empty()
                && (self.peers.is_empty() || self.tip_is_stale())
        } else {
            // Always make one query early, even if some outbound connections already exist.
            // This is useful in the case when a "fresh" node has been passed some initial
            // addresses at startup (via boot_nodes or reserved_nodes) and either their number
            // is too small or they all are in the same address group. In that case the node
            // might establish only a few OutboundBlockRelay connections and then stop establishing
            // new connections until both it's out of IBD and its tip becomes stale (following
            // the second part of the condition above).
            true
        }
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

    /// Load predefined addresses into peerdb if needed, i.e. if the db is empty and we've already
    /// queried the dns seed.
    ///
    /// Return true if peerdb has been updated.
    fn load_predefined_addresses_if_needed(&mut self) -> bool {
        if self.predefined_addresses_already_loaded {
            return false;
        }

        if self.chain_config.predefined_peer_addresses().is_empty() {
            self.predefined_addresses_already_loaded = true;
            return false;
        }

        let peerdb_is_empty = self.peerdb.known_addresses().next().is_none();

        if peerdb_is_empty && self.last_dns_query_time.is_some() {
            log::debug!("Loading predefined addresses into peerdb");

            for addr in self.chain_config.predefined_peer_addresses() {
                self.peerdb.peer_discovered(SocketAddress::new(*addr));
            }
            self.predefined_addresses_already_loaded = true;
            return true;
        }

        false
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
    /// [`PEER_MGR_HEARTBEAT_INTERVAL_MIN`] and [`PEER_MGR_HEARTBEAT_INTERVAL_MAX`] defines how
    /// often the heartbeat function is called.
    /// This is done to prevent the `PeerManager` from stalling in case the network doesn't
    /// have any events.
    ///
    /// `loop_started_sender` is a helper channel for unit testing (it notifies when it's safe to change the time with `time_getter`).
    async fn run_internal(
        &mut self,
        loop_started_sender: Option<oneshot_nofail::Sender<()>>,
    ) -> crate::Result<Never> {
        let anchor_peers = self.peerdb.anchors().clone();
        if anchor_peers.is_empty() {
            // Run heartbeat immediately to start outbound connections, but only if there are no stored anchor peers.
            self.heartbeat();
        } else {
            // Skip heartbeat to give the stored anchor peers more time to connect to prevent churn!
            // The stored anchor peers should be the first connected block relay peers.
            for anchor_address in anchor_peers {
                log::debug!("try to connect to anchor peer {anchor_address}");
                // The first peers should become anchor peers
                self.connect(
                    anchor_address,
                    OutboundConnectType::Automatic {
                        block_relay_only: true,
                    },
                );
            }
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

            let tip_is_stale = self.tip_is_stale();

            if tip_is_stale {
                early_heartbeat_needed = true;
            }

            // Periodic heartbeat call where new outbound connections are made
            if self.heartbeat_needed(early_heartbeat_needed) {
                self.heartbeat();
                early_heartbeat_needed = false;
            }

            // Query dns seed
            if self.dns_seed_query_needed() {
                self.query_dns_seed().await;
                early_heartbeat_needed = true;
            }

            if self.load_predefined_addresses_if_needed() {
                early_heartbeat_needed = true;
            }

            // Send ping requests and disconnect dead peers
            if self.ping_check_needed() {
                self.ping_check();
            }

            // Advertise local address regularly
            while next_time_resend_own_address < now {
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
    // This will be called at the end of "heartbeat" function.
    fn on_heartbeat(&mut self);
    // This will be called for both incoming and outgoing connections.
    fn on_connection_accepted(&mut self, address: SocketAddress, peer_role: PeerRole);
}

pub trait PeerManagerQueryInterface {
    #[cfg(test)]
    fn peers(&self) -> &BTreeMap<PeerId, PeerContext>;
}

impl<T, S> PeerManagerQueryInterface for PeerManager<T, S>
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    S: PeerDbStorage,
{
    #[cfg(test)]
    fn peers(&self) -> &BTreeMap<PeerId, PeerContext> {
        &self.peers
    }
}

#[cfg(test)]
mod tests;
