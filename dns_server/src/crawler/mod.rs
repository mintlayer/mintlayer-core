// Copyright (c) 2023 RBB S.r.l
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

//! # Mintlayer network crawler
//!
//! To keep things simple, the server will try to keep connections open to all reachable nodes.
//! When a new outbound connection is made, a new DNS record is added (but only for nodes on default ports).
//! When the connection is closed, the DNS record is removed.
//! When a connection fails, the server increases the backoff time between connection attempts.
//! If the number of failed connection attempts exceeds the limit, the address is removed from the list.
//! Once-reachable and newer-reachable addresses have different connection failure limits
//! (equivalent to about 1 month and about 1 hour, respectively).

pub mod storage;
pub mod storage_impl;

use std::{
    collections::{btree_map::Entry, BTreeMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use common::chain::ChainConfig;
use crypto::random::{make_pseudo_rng, seq::IteratorRandom};
use logging::log;
use p2p::{
    config::P2pConfig,
    error::P2pError,
    message::{
        AnnounceAddrRequest, PeerManagerRequest, PeerManagerResponse, PingRequest, PingResponse,
    },
    net::{
        default_backend::transport::TransportAddress,
        types::{ConnectivityEvent, PeerInfo, SyncingEvent},
        ConnectivityService, NetworkingService, SyncingMessagingService,
    },
    types::peer_address::PeerAddress,
};
use tokio::sync::mpsc;

use crate::{
    config::DnsServerConfig,
    crawler::storage::{DnsServerStorageWrite, DnsServerTransactionRw},
    error::DnsServerError,
    server::ServerCommands,
};

use self::storage::{DnsServerStorage, DnsServerStorageRead, DnsServerTransactionRo};

/// How often the server performs maintenance (tries to connect to new nodes)
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

/// How many outbound connection attempts can be made per heartbeat
const MAX_CONNECTS_PER_HEARTBEAT: usize = 10;

/// When the server drops the unreachable node address. Useful for for negative caching. Should be about an hour.
const PURGE_UNREACHABLE_FAIL_COUNT: u32 = 4;

/// When the server drops the unreachable node address that was once reachable. This should take about a month.
/// Such a long time is useful if the server itself has prolonged connectivity problems.
const PURGE_REACHABLE_FAIL_COUNT: u32 = 35;

/// Connection state of a potential node address (outbound only)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressState {
    Disconnected,
    Connecting,
    Connected,
}

/// Additional state of a potential node address
struct AddressData {
    /// Connection state
    state: AddressState,

    /// Last time when the connection state was updated
    state_updated_at: tokio::time::Instant,

    /// The number of failed connection attempts.
    /// New connection attempts are made after a progressive backoff time.
    /// Resets to 0 when an outbound connection to the address is successful.
    fail_count: u32,

    /// Whether this address was reachable at least once.
    /// Addresses that were once reachable are stored in the DB.
    was_reachable: bool,
}

pub struct Crawler<N: NetworkingService, S> {
    /// Chain config. Required for the network check
    chain_config: Arc<ChainConfig>,

    /// Backend's ConnectivityHandle
    conn: N::ConnectivityHandle,

    /// Backend's SyncingMessagingHandle
    sync: N::SyncingMessagingHandle,

    /// Map of all known addresses (including currently unreachable)
    addresses: BTreeMap<N::Address, AddressData>,

    /// Map of all currently connected peers
    peers: BTreeMap<N::PeerId, N::Address>,

    /// Storage implementation
    storage: S,

    /// Channel used to manage the DNS server
    command_tx: mpsc::UnboundedSender<ServerCommands>,
}

impl<N: NetworkingService + 'static, S: DnsServerStorage> Crawler<N, S>
where
    N::SyncingMessagingHandle: SyncingMessagingService<N>,
    N::ConnectivityHandle: ConnectivityService<N>,
    DnsServerError: From<<<N as NetworkingService>::Address as FromStr>::Err>,
{
    pub async fn new(
        config: Arc<DnsServerConfig>,
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        transport: N::Transport,
        storage: S,
        command_tx: mpsc::UnboundedSender<ServerCommands>,
    ) -> Result<Self, DnsServerError> {
        // Load all persistent addresses
        let tx = storage.transaction_ro()?;
        let mut addresses = BTreeMap::new();
        for address in tx.get_addresses()?.iter().filter_map(|address| address.parse().ok()) {
            Self::new_address(&mut addresses, address, true);
        }
        tx.close();

        // Add addresses that were specified from the command line as reachable
        for address in config.add_node.iter() {
            let address = address.parse()?;
            Self::new_address(&mut addresses, address, true);
        }

        let (conn, sync) = N::start(
            transport,
            vec![],
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
        )
        .await?;

        Ok(Self {
            chain_config,
            conn,
            sync,
            addresses,
            peers: BTreeMap::new(),
            storage,
            command_tx,
        })
    }

    fn handle_conn_request(
        &mut self,
        _peer_id: N::PeerId,
        request_id: N::PeerRequestId,
        request: PeerManagerRequest,
    ) {
        match request {
            PeerManagerRequest::AddrListRequest(_) => {
                // Ignored
            }
            PeerManagerRequest::AnnounceAddrRequest(AnnounceAddrRequest { address }) => {
                // TODO: Rate limit AnnounceAddrRequest requests
                if let Some(address) = TransportAddress::from_peer_address(&address) {
                    Self::new_address(&mut self.addresses, address, false);
                }
            }
            PeerManagerRequest::PingRequest(PingRequest { nonce }) => {
                let _ = self.conn.send_response(
                    request_id,
                    PeerManagerResponse::PingResponse(PingResponse { nonce }),
                );
            }
        }
    }

    fn handle_conn_response(
        &mut self,
        _peer_id: N::PeerId,
        _request_id: N::PeerRequestId,
        _response: PeerManagerResponse,
    ) {
        // Ignore all
    }

    fn handle_outbound_accepted(
        &mut self,
        address: N::Address,
        peer_info: PeerInfo<N::PeerId>,
        _receiver_address: Option<PeerAddress>,
    ) {
        let address_data = self
            .addresses
            .get_mut(&address)
            .expect("address in the Connecting state must be known");
        let valid = peer_info.network == *self.chain_config.magic_bytes();

        if !valid {
            log::debug!("invalid peer detected at {}", address.to_string());
            self.conn.disconnect(peer_info.peer_id).expect("disconnect must succeed");
            Self::change_address_state(
                &self.chain_config,
                &address,
                address_data,
                AddressState::Disconnected,
                &mut self.storage,
                &self.command_tx,
            );
            return;
        }

        Self::change_address_state(
            &self.chain_config,
            &address,
            address_data,
            AddressState::Connected,
            &mut self.storage,
            &self.command_tx,
        );
        self.peers.insert(peer_info.peer_id, address);
    }

    fn handle_inbound_accepted(
        &mut self,
        _address: N::Address,
        _peer_info: PeerInfo<N::PeerId>,
        _receiver_address: Option<PeerAddress>,
    ) {
        unreachable!("unexpected inbound connection");
    }

    fn handle_connection_error(&mut self, address: N::Address, _error: P2pError) {
        let address_data = self
            .addresses
            .get_mut(&address)
            .expect("address in the Connecting state must be known");
        Self::change_address_state(
            &self.chain_config,
            &address,
            address_data,
            AddressState::Disconnected,
            &mut self.storage,
            &self.command_tx,
        );
    }

    fn handle_connection_closed(&mut self, peer_id: N::PeerId) {
        if let Some(address) = self.peers.remove(&peer_id) {
            let address_data = self
                .addresses
                .get_mut(&address)
                .expect("address in the Connected state must be known");
            Self::change_address_state(
                &self.chain_config,
                &address,
                address_data,
                AddressState::Disconnected,
                &mut self.storage,
                &self.command_tx,
            );
        }
    }

    fn handle_misbehaved(&mut self, _peer_id: N::PeerId, _error: P2pError) {
        // Ignore all misbehave reports
    }

    fn handle_conn_event(&mut self, event: ConnectivityEvent<N>) {
        match event {
            ConnectivityEvent::Request {
                peer_id,
                request_id,
                request,
            } => {
                self.handle_conn_request(peer_id, request_id, request);
            }
            ConnectivityEvent::Response {
                peer_id,
                request_id,
                response,
            } => {
                self.handle_conn_response(peer_id, request_id, response);
            }
            ConnectivityEvent::OutboundAccepted {
                address,
                peer_info,
                receiver_address,
            } => {
                self.handle_outbound_accepted(address, peer_info, receiver_address);
            }
            ConnectivityEvent::InboundAccepted {
                address,
                peer_info,
                receiver_address,
            } => {
                self.handle_inbound_accepted(address, peer_info, receiver_address);
            }
            ConnectivityEvent::ConnectionError { address, error } => {
                self.handle_connection_error(address, error);
            }
            ConnectivityEvent::ConnectionClosed { peer_id } => {
                self.handle_connection_closed(peer_id);
            }
            ConnectivityEvent::Misbehaved { peer_id, error } => {
                self.handle_misbehaved(peer_id, error);
            }
        }
    }

    fn handle_sync_event(&mut self, _event: SyncingEvent<N>) {
        // Ignore all sync events
    }

    fn new_address(
        addresses: &mut BTreeMap<N::Address, AddressData>,
        address: N::Address,
        was_reachable: bool,
    ) {
        if let Entry::Vacant(vacant) = addresses.entry(address.clone()) {
            log::debug!("new address {} added", address.to_string());
            vacant.insert(AddressData {
                state: AddressState::Disconnected,
                state_updated_at: tokio::time::Instant::now(),
                fail_count: 0,
                was_reachable,
            });
        }
    }

    /// Update address state.
    ///
    /// The only place where the address state can be updated.
    fn change_address_state(
        chain_config: &ChainConfig,
        address: &N::Address,
        address_data: &mut AddressData,
        new_state: AddressState,
        storage: &mut S,
        command_tx: &mpsc::UnboundedSender<ServerCommands>,
    ) {
        if address_data.state == new_state {
            return;
        }

        log::debug!(
            "change address {} state to {:?}",
            address.to_string(),
            new_state
        );
        address_data.state = new_state;
        address_data.state_updated_at = tokio::time::Instant::now();

        // Only add nodes listening on the default port to DNS
        let dns_ip: Option<IpAddr> = match address.as_peer_address() {
            PeerAddress::Ip4(addr) if addr.port == chain_config.p2p_port() => {
                Some(Ipv4Addr::from(addr.ip).into())
            }
            PeerAddress::Ip6(addr) if addr.port == chain_config.p2p_port() => {
                Some(Ipv6Addr::from(addr.ip).into())
            }
            _ => None,
        };

        match new_state {
            AddressState::Connecting => {
                // Do nothing
            }
            AddressState::Connected => {
                // New reachable address discovered
                let mut tx = storage.transaction_rw().expect("tx must succeed");
                tx.add_address(&address.to_string()).expect("adding address must succeed");
                tx.commit().expect("tx commit must succeed");

                if let Some(ip) = dns_ip {
                    command_tx.send(ServerCommands::AddAddress(ip)).expect("sending must succeed");
                }

                address_data.fail_count = 0;
                address_data.was_reachable = true;
            }
            AddressState::Disconnected => {
                if let Some(ip) = dns_ip {
                    command_tx.send(ServerCommands::DelAddress(ip)).expect("sending must succeed");
                }

                address_data.fail_count += 1;
            }
        }
    }

    /// Returns true when it is time to attempt a new outbound connection
    fn connect_now(now: tokio::time::Instant, address_data: &AddressData) -> bool {
        match address_data.state {
            AddressState::Connected | AddressState::Connecting => false,
            AddressState::Disconnected => {
                let age = now.duration_since(address_data.state_updated_at);

                match address_data.fail_count {
                    0 => true,
                    1 => age > Duration::from_secs(10),
                    2 => age > Duration::from_secs(60),
                    3 => age > Duration::from_secs(360),
                    4 => age > Duration::from_secs(3600),
                    5 => age > Duration::from_secs(3 * 3600),
                    6 => age > Duration::from_secs(6 * 3600),
                    7 => age > Duration::from_secs(12 * 3600),
                    _ => age > Duration::from_secs(24 * 3600),
                }
            }
        }
    }

    /// Returns true if the address should be kept in memory
    fn retain_address(
        address: &N::Address,
        address_data: &mut AddressData,
        storage: &mut S,
    ) -> bool {
        if address_data.state == AddressState::Disconnected
            && address_data.was_reachable
            && address_data.fail_count >= PURGE_REACHABLE_FAIL_COUNT
        {
            log::debug!("purge old (once reachable) address {}", address.to_string());

            let mut tx = storage.transaction_rw().expect("tx must succeed");
            tx.del_address(&address.to_string()).expect("adding address must succeed");
            tx.commit().expect("tx commit must succeed");

            return false;
        }

        if address_data.state == AddressState::Disconnected
            && !address_data.was_reachable
            && address_data.fail_count >= PURGE_UNREACHABLE_FAIL_COUNT
        {
            log::debug!("purge old (unreachable) address {}", address.to_string());

            return false;
        }

        true
    }

    /// Address list maintaince
    fn heartbeat(&mut self) {
        let now = tokio::time::Instant::now();

        let connecting_addresses = self
            .addresses
            .iter_mut()
            .filter(|(_address, address_data)| Self::connect_now(now, address_data))
            .choose_multiple(&mut make_pseudo_rng(), MAX_CONNECTS_PER_HEARTBEAT);

        for (address, address_data) in connecting_addresses {
            Self::change_address_state(
                &self.chain_config,
                address,
                address_data,
                AddressState::Connecting,
                &mut self.storage,
                &self.command_tx,
            );

            let res = self.conn.connect(address.clone());
            if let Err(e) = res {
                log::debug!("connection to {} failed: {}", address.to_string(), e);
                Self::change_address_state(
                    &self.chain_config,
                    address,
                    address_data,
                    AddressState::Disconnected,
                    &mut self.storage,
                    &self.command_tx,
                );
            }
        }

        self.addresses.retain(|address, address_data| {
            Self::retain_address(address, address_data, &mut self.storage)
        });
    }

    pub async fn run(mut self) -> Result<void::Void, DnsServerError> {
        let mut heartbeat_timer = tokio::time::interval(HEARTBEAT_INTERVAL);

        loop {
            tokio::select! {
                event_res = self.conn.poll_next() => {
                    self.handle_conn_event(event_res?);
                },
                event_res = self.sync.poll_next() => {
                    self.handle_sync_event(event_res?);
                },
                _ = heartbeat_timer.tick() => {
                    self.heartbeat();
                },
            }
        }
    }
}
