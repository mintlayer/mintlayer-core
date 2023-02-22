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
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use common::chain::ChainConfig;
use crypto::random::make_pseudo_rng;
use p2p::{
    message::{AnnounceAddrRequest, PeerManagerMessage, PingRequest, PingResponse},
    net::{
        default_backend::transport::TransportAddress,
        types::{ConnectivityEvent, SyncingEvent},
        ConnectivityService, NetworkingService, SyncingMessagingService,
    },
    peer_manager::global_ip::IsGlobalIp,
    types::{peer_address::PeerAddress, peer_id::PeerId},
};
use tokio::{sync::mpsc, time::Instant};

use crate::{dns_server::DnsServerCommand, error::DnsServerError};

use self::storage::{
    DnsServerStorage, DnsServerStorageRead, DnsServerStorageWrite, DnsServerTransactionRo,
    DnsServerTransactionRw,
};

use super::crawler::{Crawler, CrawlerCommand, CrawlerEvent};

/// How often the server performs maintenance (tries to connect to new nodes)
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

const STORAGE_VERSION: u32 = 1;

#[derive(Clone)]
pub struct CrawlerManagerConfig {
    /// Manually specified list of nodes to connect to
    pub add_node: Vec<String>,

    /// Default p2p port on which nodes normally accept inbound connections;
    /// the DNS server has no way to communicate port numbers,
    /// and hence we only add addresses that are reachable through this default port
    pub default_p2p_port: u16,
}

pub struct CrawlerManager<N: NetworkingService, S> {
    /// The time when the crawler was updated last time
    last_crawler_timer: Instant,

    /// Crawler
    crawler: Crawler<N::Address>,

    /// Config
    config: CrawlerManagerConfig,

    /// Backend's ConnectivityHandle
    conn: N::ConnectivityHandle,

    /// Backend's SyncingMessagingHandle
    sync: N::SyncingMessagingHandle,

    /// Storage implementation
    storage: S,

    /// Channel used to manage the DNS server
    dns_server_cmd_tx: mpsc::UnboundedSender<DnsServerCommand>,
}

impl<N: NetworkingService, S: DnsServerStorage> CrawlerManager<N, S>
where
    N::SyncingMessagingHandle: SyncingMessagingService<N>,
    N::ConnectivityHandle: ConnectivityService<N>,
    DnsServerError: From<<<N as NetworkingService>::Address as FromStr>::Err>,
{
    pub fn new(
        config: CrawlerManagerConfig,
        chain_config: Arc<ChainConfig>,
        conn: N::ConnectivityHandle,
        sync: N::SyncingMessagingHandle,
        storage: S,
        dns_server_cmd_tx: mpsc::UnboundedSender<DnsServerCommand>,
    ) -> Result<Self, DnsServerError> {
        let last_crawler_timer = tokio::time::Instant::now();

        // Addresses that are stored in the DB as reachable
        let loaded_addresses: BTreeSet<N::Address> = Self::load_storage(&storage)?;

        // Addresses listed as reachable from the command line
        let added_addresses: BTreeSet<N::Address> = config
            .add_node
            .iter()
            .map(|addr| addr.parse())
            .collect::<Result<BTreeSet<N::Address>, _>>()?;

        assert!(conn.local_addresses().is_empty());

        let crawler = Crawler::new(chain_config, loaded_addresses, added_addresses);

        Ok(Self {
            last_crawler_timer,
            crawler,
            config,
            conn,
            sync,
            storage,
            dns_server_cmd_tx,
        })
    }

    fn load_storage(storage: &S) -> Result<BTreeSet<N::Address>, DnsServerError> {
        let tx = storage.transaction_ro()?;
        let version = tx.get_version()?;
        tx.close();

        match version {
            None => Self::init_storage(storage),
            Some(STORAGE_VERSION) => Self::load_storage_v1(storage),
            Some(_version) => Err(DnsServerError::Other("Unexpected storage version")),
        }
    }

    fn init_storage(storage: &S) -> Result<BTreeSet<N::Address>, DnsServerError> {
        let mut tx = storage.transaction_rw()?;
        tx.set_version(STORAGE_VERSION)?;
        tx.commit()?;
        Ok(BTreeSet::new())
    }

    fn load_storage_v1(storage: &S) -> Result<BTreeSet<N::Address>, DnsServerError> {
        let tx = storage.transaction_ro()?;
        let addresses =
            tx.get_addresses()?.iter().filter_map(|address| address.parse().ok()).collect();
        Ok(addresses)
    }

    fn handle_conn_message(&mut self, peer_id: PeerId, message: PeerManagerMessage) {
        match message {
            PeerManagerMessage::AddrListRequest(_) => {
                // Ignored
            }
            PeerManagerMessage::AnnounceAddrRequest(AnnounceAddrRequest { address }) => {
                // TODO: Rate limit `AnnounceAddrRequest` requests from a specific peer to prevent DoS attack,
                // when too many invalid addresses are announced, preventing the server from discovering new addresses.
                // For example, Bitcoin Core allows 0.1 address/sec.
                if let Some(address) = TransportAddress::from_peer_address(&address, false) {
                    self.send_crawler_event(CrawlerEvent::NewAddress { address });
                }
            }
            PeerManagerMessage::PingRequest(PingRequest { nonce }) => {
                self.conn
                    .send_message(
                        peer_id,
                        PeerManagerMessage::PingResponse(PingResponse { nonce }),
                    )
                    .expect("send_message must succeed");
            }
            PeerManagerMessage::AddrListResponse(_) => {}
            PeerManagerMessage::PingResponse(_) => {}
        }
    }

    fn handle_conn_event(&mut self, event: ConnectivityEvent<N::Address>) {
        match event {
            ConnectivityEvent::Message { peer, message } => {
                self.handle_conn_message(peer, message);
            }
            ConnectivityEvent::OutboundAccepted {
                address,
                peer_info,
                receiver_address: _,
            } => {
                self.send_crawler_event(CrawlerEvent::Connected { peer_info, address });
            }
            ConnectivityEvent::InboundAccepted {
                address: _,
                peer_info: _,
                receiver_address: _,
            } => {
                unreachable!("unexpected inbound connection");
            }
            ConnectivityEvent::ConnectionError { address, error } => {
                self.send_crawler_event(CrawlerEvent::ConnectionError { address, error });
            }
            ConnectivityEvent::ConnectionClosed { peer_id } => {
                self.send_crawler_event(CrawlerEvent::Disconnected { peer_id });
            }
            ConnectivityEvent::Misbehaved {
                peer_id: _,
                error: _,
            } => {
                // Ignore all misbehave reports
                // TODO: Should we ban peers when they send unexpected messages?
            }
        }
    }

    fn handle_sync_event(&mut self, _event: SyncingEvent) {
        // Ignore all sync events
    }

    fn heartbeat(&mut self) {
        let now = tokio::time::Instant::now();
        let period = now.duration_since(self.last_crawler_timer);
        self.last_crawler_timer = now;

        self.send_crawler_event(CrawlerEvent::Timer { period });
    }

    fn get_dns_ip(address: &N::Address, default_p2p_port: u16) -> Option<IpAddr> {
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
        cmd: CrawlerCommand<N::Address>,
        config: &CrawlerManagerConfig,
        conn: &mut N::ConnectivityHandle,
        dns_server_cmd_tx: &mpsc::UnboundedSender<DnsServerCommand>,
        storage: &S,
    ) {
        match cmd {
            CrawlerCommand::Connect { address } => {
                conn.connect(address).expect("connect must succeed");
            }
            CrawlerCommand::Disconnect { peer_id } => {
                conn.disconnect(peer_id).expect("disconnect must succeed");
            }
            CrawlerCommand::UpdateAddress {
                address,
                old_state,
                new_state,
            } => {
                match (
                    Self::get_dns_ip(&address, config.default_p2p_port),
                    old_state.is_reachable(),
                    new_state.is_reachable(),
                ) {
                    (Some(ip), false, true) => {
                        dns_server_cmd_tx
                            .send(DnsServerCommand::AddAddress(ip))
                            .expect("sending must succeed (AddAddress)");
                    }
                    (Some(ip), true, false) => {
                        dns_server_cmd_tx
                            .send(DnsServerCommand::DelAddress(ip))
                            .expect("sending must succeed (DelAddress)");
                    }
                    _ => {}
                }

                match (old_state.is_persistent(), new_state.is_persistent()) {
                    (false, true) => {
                        storage::update_db(storage, |tx| tx.add_address(&address.to_string()))
                            .expect("update_db must succeed (add_address)");
                    }
                    (true, false) => {
                        storage::update_db(storage, |tx| tx.del_address(&address.to_string()))
                            .expect("update_db must succeed (del_address)");
                    }
                    _ => {}
                }
            }
        }
    }

    fn send_crawler_event(&mut self, event: CrawlerEvent<N::Address>) {
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

    pub async fn run(&mut self) -> Result<void::Void, DnsServerError> {
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

#[cfg(test)]
mod tests;
