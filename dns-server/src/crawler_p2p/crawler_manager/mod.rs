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

pub mod storage;
pub mod storage_impl;

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use chainstate::ban_score::BanScore;
use common::{chain::ChainConfig, primitives::time::Time, time_getter::TimeGetter};
use futures::never::Never;
use logging::log;
use p2p::{
    error::{P2pError, ProtocolError},
    message::{
        AddrListRequest, AddrListResponse, AnnounceAddrRequest, PeerManagerMessage, PingRequest,
        PingResponse,
    },
    net::{
        types::{ConnectivityEvent, SyncingEvent},
        ConnectivityService, NetworkingService, SyncingEventReceiver,
    },
    peer_manager::{
        ip_or_socket_address_to_peer_address,
        peerdb_common::{storage::update_db, StorageVersion, TransactionRo, TransactionRw},
    },
    types::{
        bannable_address::BannableAddress, peer_address::PeerAddress, peer_id::PeerId,
        socket_address::SocketAddress, IsGlobalIp,
    },
};
use randomness::make_pseudo_rng;
use tokio::sync::mpsc;
use utils::{ensure, tap_log::TapLog};
use utils_networking::IpOrSocketAddress;

use crate::{
    crawler_p2p::crawler_manager::storage::AddressInfo, dns_server::DnsServerCommand,
    error::DnsServerError,
};

use self::storage::{DnsServerStorage, DnsServerStorageRead, DnsServerStorageWrite};

use super::crawler::{Crawler, CrawlerCommand, CrawlerConfig, CrawlerEvent};

/// How often the server performs maintenance (tries to connect to new nodes)
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

const CURRENT_STORAGE_VERSION: StorageVersion = StorageVersion::new(2);

#[derive(Clone)]
pub struct CrawlerManagerConfig {
    /// Manually specified list of nodes to connect to
    pub reserved_nodes: Vec<IpOrSocketAddress>,

    /// Default p2p port on which nodes normally accept inbound connections;
    /// the DNS server has no way to communicate port numbers,
    /// and hence we only add addresses that are reachable through this default port
    pub default_p2p_port: u16,
}

pub struct CrawlerManager<N: NetworkingService, S> {
    time_getter: TimeGetter,

    /// The time when the crawler was updated last time
    last_crawler_timer: Time,

    /// Crawler
    crawler: Crawler,

    /// Config
    config: CrawlerManagerConfig,

    /// Backend's ConnectivityHandle
    conn: N::ConnectivityHandle,

    /// Backend's SyncingMessagingHandle
    sync: N::SyncingEventReceiver,

    /// Storage implementation
    storage: S,

    /// Channel used to manage the DNS server
    dns_server_cmd_tx: mpsc::UnboundedSender<DnsServerCommand>,
}

// Note: "pub" access is only needed because of the "load_storage_for_tests" function.
pub struct LoadedStorage {
    pub known_addresses: BTreeMap<SocketAddress, AddressInfo>,
    pub banned_addresses: BTreeMap<BannableAddress, Time>,
}

impl LoadedStorage {
    pub fn new() -> Self {
        Self {
            known_addresses: BTreeMap::new(),
            banned_addresses: BTreeMap::new(),
        }
    }
}

impl<N: NetworkingService, S: DnsServerStorage> CrawlerManager<N, S>
where
    N::SyncingEventReceiver: SyncingEventReceiver,
    N::ConnectivityHandle: ConnectivityService<N>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        time_getter: TimeGetter,
        config: CrawlerManagerConfig,
        crawler_config: CrawlerConfig,
        chain_config: Arc<ChainConfig>,
        conn: N::ConnectivityHandle,
        sync: N::SyncingEventReceiver,
        storage: S,
        dns_server_cmd_tx: mpsc::UnboundedSender<DnsServerCommand>,
    ) -> crate::Result<Self> {
        let last_crawler_timer = time_getter.get_time();

        // Addresses that are stored in the DB as reachable
        let loaded_storage = Self::load_storage(&storage)?;

        // Addresses listed as reachable from the command line
        let reserved_addresses: BTreeSet<SocketAddress> = config
            .reserved_nodes
            .iter()
            .map(|addr| ip_or_socket_address_to_peer_address(addr, &chain_config))
            .collect::<BTreeSet<SocketAddress>>();

        assert!(conn.local_addresses().is_empty());

        log::debug!(
            "Got {} known addresses, {} banned addresses, {} reserved addresses",
            loaded_storage.known_addresses.len(),
            loaded_storage.banned_addresses.len(),
            reserved_addresses.len()
        );

        let crawler = Crawler::new(
            last_crawler_timer,
            chain_config,
            crawler_config,
            loaded_storage.known_addresses,
            loaded_storage.banned_addresses,
            reserved_addresses,
        );

        Ok(Self {
            time_getter,
            last_crawler_timer,
            crawler,
            config,
            conn,
            sync,
            storage,
            dns_server_cmd_tx,
        })
    }

    fn load_storage(storage: &S) -> crate::Result<LoadedStorage> {
        let tx = storage.transaction_ro()?;
        let version = tx.get_version()?;
        tx.close();

        match version {
            None => Self::init_storage(storage),
            Some(CURRENT_STORAGE_VERSION) => Self::load_storage_impl(storage),
            Some(version) => Err(DnsServerError::StorageVersionMismatch {
                expected_version: CURRENT_STORAGE_VERSION,
                actual_version: version,
            }),
        }
    }

    fn init_storage(storage: &S) -> crate::Result<LoadedStorage> {
        let mut tx = storage.transaction_rw()?;
        tx.set_version(CURRENT_STORAGE_VERSION)?;
        tx.commit()?;
        Ok(LoadedStorage::new())
    }

    fn load_storage_impl(storage: &S) -> crate::Result<LoadedStorage> {
        let tx = storage.transaction_ro()?;
        let known_addresses = tx.get_addresses()?.into_iter().collect::<BTreeMap<_, _>>();

        let banned_addresses = tx.get_banned_addresses()?.into_iter().collect::<BTreeMap<_, _>>();

        Ok(LoadedStorage {
            known_addresses,
            banned_addresses,
        })
    }

    fn handle_conn_message(
        &mut self,
        peer_id: PeerId,
        message: PeerManagerMessage,
    ) -> p2p::Result<()> {
        match message {
            PeerManagerMessage::AddrListRequest(_) => {
                // Ignored
                Ok(())
            }
            PeerManagerMessage::AnnounceAddrRequest(AnnounceAddrRequest { address }) => {
                log::debug!("Got address announcement from peer {peer_id} ({address})");
                if let Some(address) = address.as_discoverable_socket_address(false) {
                    self.send_crawler_event(CrawlerEvent::AddressAnnouncement {
                        address,
                        sender: peer_id,
                    });
                }

                Ok(())
            }
            PeerManagerMessage::PingRequest(PingRequest { nonce }) => {
                self.conn
                    .send_message(
                        peer_id,
                        PeerManagerMessage::PingResponse(PingResponse { nonce }),
                    )
                    .expect("send_message must succeed");

                Ok(())
            }
            PeerManagerMessage::AddrListResponse(AddrListResponse { addresses }) => {
                log::debug!(
                    "Got address list response from peer {}, address count = ({})",
                    peer_id,
                    addresses.len()
                );

                ensure!(
                    addresses.len() <= *p2p::protocol::MaxAddrListResponseAddressCount::default(),
                    P2pError::ProtocolError(ProtocolError::AddressListLimitExceeded)
                );

                let addresses = addresses
                    .iter()
                    .filter_map(|addr| addr.as_discoverable_socket_address(false))
                    .collect::<Vec<_>>();

                self.send_crawler_event(CrawlerEvent::AddressListResponse {
                    addresses,
                    sender: peer_id,
                });

                Ok(())
            }
            PeerManagerMessage::PingResponse(_) => Ok(()),

            PeerManagerMessage::WillDisconnect(_) => {
                // Since the peer is going to disconnect us anyway, do it ourselves right away.
                // We don't care about any errors here.
                let _ = self
                    .conn
                    .disconnect(peer_id, None)
                    .log_lvl_pfx(log::Level::Debug, "disconnection failed");
                Ok(())
            }
        }
    }

    fn handle_conn_event(&mut self, event: ConnectivityEvent) {
        match event {
            ConnectivityEvent::Message { peer_id, message } => {
                let result = self.handle_conn_message(peer_id, message);

                if let Err(error) = result {
                    if error.ban_score() > 0 {
                        self.send_crawler_event(CrawlerEvent::Misbehaved { peer_id, error });
                    }
                }
            }
            ConnectivityEvent::OutboundAccepted {
                peer_address,
                bind_address: _,
                peer_info,
                node_address_as_seen_by_peer: _,
            } => {
                // Allow reading input messages from the connected peer
                self.conn.accept(peer_info.peer_id).expect("accept must succeed");

                self.send_crawler_event(CrawlerEvent::Connected {
                    peer_info,
                    address: peer_address,
                });
            }
            ConnectivityEvent::InboundAccepted {
                peer_address: _,
                bind_address: _,
                peer_info: _,
                node_address_as_seen_by_peer: _,
            } => {
                unreachable!("unexpected inbound connection");
            }
            ConnectivityEvent::ConnectionError {
                peer_address,
                error,
            } => {
                self.send_crawler_event(CrawlerEvent::ConnectionError {
                    address: peer_address,
                    error,
                });
            }
            ConnectivityEvent::MisbehavedOnHandshake {
                peer_address,
                error,
            } => {
                self.send_crawler_event(CrawlerEvent::MisbehavedOnHandshake {
                    address: peer_address,
                    error,
                });
            }
            ConnectivityEvent::ConnectionClosed { peer_id } => {
                self.send_crawler_event(CrawlerEvent::Disconnected { peer_id });
            }
            ConnectivityEvent::Misbehaved { peer_id, error } => {
                self.send_crawler_event(CrawlerEvent::Misbehaved { peer_id, error });
            }
        }
    }

    fn handle_sync_event(&mut self, _event: SyncingEvent) {
        // Ignore all sync events
    }

    fn heartbeat(&mut self) {
        let now = self.time_getter.get_time();
        let period = now.saturating_sub(self.last_crawler_timer);
        self.last_crawler_timer = now;

        self.send_crawler_event(CrawlerEvent::Timer { period });
    }

    fn get_dns_ip(address: &SocketAddress, default_p2p_port: u16) -> Option<IpAddr> {
        // Only add nodes listening on the default port to DNS
        match address.as_peer_address() {
            PeerAddress::Ip4(addr)
                if Ipv4Addr::from(addr.ip).is_global_unicast_ip()
                    && addr.port == default_p2p_port =>
            {
                Some(Ipv4Addr::from(addr.ip).into())
            }
            PeerAddress::Ip6(addr)
                if Ipv6Addr::from(addr.ip).is_global_unicast_ip()
                    && addr.port == default_p2p_port =>
            {
                Some(Ipv6Addr::from(addr.ip).into())
            }
            _ => None,
        }
    }

    fn handle_crawler_cmd(
        cmd: CrawlerCommand,
        config: &CrawlerManagerConfig,
        conn: &mut N::ConnectivityHandle,
        dns_server_cmd_tx: &mpsc::UnboundedSender<DnsServerCommand>,
        storage: &S,
    ) {
        match cmd {
            CrawlerCommand::Connect { address } => {
                conn.connect(address, None).expect("connect must succeed");
            }
            CrawlerCommand::RequestAddresses { peer_id } => {
                log::debug!("Requesting addresses from peer {peer_id}");

                conn.send_message(
                    peer_id,
                    PeerManagerMessage::AddrListRequest(AddrListRequest {}),
                )
                .expect("send_message must succeed");
            }
            CrawlerCommand::Disconnect { peer_id } => {
                conn.disconnect(peer_id, None).expect("disconnect must succeed");
            }
            CrawlerCommand::UpdateAddress {
                address,
                old_state,
                new_state,
            } => {
                let was_reachable = old_state.is_reachable();
                let is_reachable = new_state.is_reachable();
                log::debug!(
                    "Got address update for {}, was_reachable = {}, is_reachable = {}",
                    address,
                    was_reachable,
                    is_reachable
                );

                match (
                    Self::get_dns_ip(&address, config.default_p2p_port),
                    was_reachable,
                    is_reachable,
                ) {
                    (Some(ip), false, true) => {
                        let connection_info = new_state
                            .connection_info()
                            .expect("Connection info must be present for a reachable address");
                        dns_server_cmd_tx
                            .send(DnsServerCommand::AddAddress(
                                ip,
                                connection_info.peer_software_info.clone(),
                            ))
                            .expect("sending must succeed (AddAddress)");
                    }
                    (Some(ip), true, false) => {
                        dns_server_cmd_tx
                            .send(DnsServerCommand::DelAddress(ip))
                            .expect("sending must succeed (DelAddress)");
                    }
                    _ => {}
                }

                if new_state.is_persistent() {
                    let connection_info = new_state
                        .connection_info()
                        .expect("Connection info must be present for a persistent address");
                    update_db(storage, |tx| {
                        tx.add_address(
                            &address,
                            &AddressInfo {
                                software_info: connection_info.peer_software_info.clone(),
                                last_addr_list_request_time: connection_info
                                    .last_addr_list_request_time
                                    .map(|time| time.as_duration_since_epoch()),
                            },
                        )
                    })
                    .expect("update_db must succeed (add_address)");
                } else if old_state.is_persistent() {
                    update_db(storage, |tx| tx.del_address(&address))
                        .expect("update_db must succeed (del_address)");
                }
            }
            CrawlerCommand::MarkAsBanned { address, ban_until } => {
                update_db(storage, |tx| tx.add_banned_address(&address, ban_until))
                    .expect("update_db must succeed (add_banned_address)");
            }
            CrawlerCommand::RemoveBannedStatus { address } => {
                update_db(storage, |tx| tx.del_banned_address(&address))
                    .expect("update_db must succeed (del_banned_address)");
            }
        }
    }

    fn send_crawler_event(&mut self, event: CrawlerEvent) {
        self.crawler.step(
            event,
            &mut |cmd| {
                Self::handle_crawler_cmd(
                    cmd,
                    &self.config,
                    &mut self.conn,
                    &self.dns_server_cmd_tx,
                    &self.storage,
                )
            },
            &mut make_pseudo_rng(),
        );
    }

    pub async fn run(&mut self) -> crate::Result<Never> {
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

    #[cfg(test)]
    pub fn load_storage_for_tests(&self) -> crate::Result<LoadedStorage> {
        Self::load_storage(&self.storage)
    }
}

#[cfg(test)]
mod tests;
