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

//! # Mintlayer DNS seed server

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
};

use common::chain::ChainConfig;
use crypto::random::{make_pseudo_rng, seq::IteratorRandom, Rng, SliceRandom};
use futures::never::Never;
use logging::log;
use tokio::{net::UdpSocket, sync::mpsc};
use trust_dns_client::{
    proto::rr::{LowerName, RrKey},
    rr::{
        rdata::{NS, SOA},
        Name, RData, RecordSet, RecordType,
    },
};
use trust_dns_server::{
    authority::{
        AuthLookup, Authority, Catalog, LookupError, LookupOptions, MessageRequest, UpdateResult,
        ZoneType,
    },
    server::RequestInfo,
    store::in_memory::InMemoryAuthority,
    ServerFuture,
};
use utils::atomics::RelaxedAtomicU32;

use crate::{
    config::DnsServerConfig, crawler_p2p::crawler::address_data::SoftwareInfo,
    error::DnsServerError,
};

#[derive(Debug, PartialEq, Eq)]
pub enum DnsServerCommand {
    AddAddress(IpAddr, SoftwareInfo),

    DelAddress(IpAddr),
}

pub struct DnsServer {
    auth: Arc<AuthorityImpl>,

    server: ServerFuture<Catalog>,

    cmd_rx: mpsc::UnboundedReceiver<DnsServerCommand>,
}

/// Same values as in `https://github.com/sipa/bitcoin-seeder/blob/3ef602de83a76bc95a06867d4bfc239f13992140/dns.cpp`
const SOA_REFRESH: i32 = 604800;
const SOA_RETRY: i32 = 86400;
const SOA_EXPIRE: i32 = 2592000;
const SOA_MINIMUM: u32 = 604800;

// Same values as in `https://github.com/sipa/bitcoin-seeder/blob/3ef602de83a76bc95a06867d4bfc239f13992140/dns.cpp`
const TTL_IP: u32 = 360; // FIXME
const TTL_NS: u32 = 21600;
const TTL_SOA: u32 = 21600;

/// Maximum number of IPv4 addresses in result
const MAX_IPV4_RECORDS: usize = 24;

/// Maximum number of IPv6 addresses in result
const MAX_IPV6_RECORDS: usize = 14;

/// When publishing addresses, we give preference to nodes that have the same software version as
/// the dns server itself.
/// This constant is a number between 0 and 1 that determines how many addresses of same-version
/// nodes will be returned compared to nodes of any other version.
const SAME_SOFTWARE_VERSION_PEERS_RATIO: f64 = 0.8;

impl DnsServer {
    pub async fn new(
        config: Arc<DnsServerConfig>,
        chain_config: Arc<ChainConfig>,
        cmd_rx: mpsc::UnboundedReceiver<DnsServerCommand>,
    ) -> crate::Result<Self> {
        let inner = InMemoryAuthority::empty(config.host.clone(), ZoneType::Primary, false);

        let auth = Arc::new(AuthorityImpl {
            chain_config,
            serial: Default::default(),
            host: config.host.clone(),
            nameserver: config.nameserver.clone(),
            mbox: config.mbox.clone(),
            inner,
            ip4: Default::default(),
            ip6: Default::default(),
        });

        let mut catalog = Catalog::new();

        catalog.upsert(config.host.clone().into(), Box::new(Arc::clone(&auth)));

        let mut server = ServerFuture::new(catalog);

        for bind_addr in config.bind_addr.iter() {
            let socket_addr: SocketAddr = bind_addr.parse()?;
            let udp_socket = UdpSocket::bind(socket_addr).await?;
            server.register_socket(udp_socket);
        }

        Ok(Self {
            auth,
            server,
            cmd_rx,
        })
    }

    pub async fn run(self) -> crate::Result<Never> {
        let DnsServer {
            auth,
            server,
            mut cmd_rx,
        } = self;

        tokio::spawn(async move {
            while let Some(command) = cmd_rx.recv().await {
                handle_command(&auth, command);
            }
        });

        server.block_until_done().await?;

        Err(DnsServerError::Other(
            "trust_dns_server terminated unexpectedly",
        ))
    }
}

/// Wrapper for InMemoryAuthority that selects random addresses every second
struct AuthorityImpl {
    chain_config: Arc<ChainConfig>,
    serial: RelaxedAtomicU32,
    host: Name,
    nameserver: Option<Name>,
    mbox: Option<Name>,
    inner: InMemoryAuthority,
    ip4: Mutex<Vec<(Ipv4Addr, SoftwareInfo)>>,
    ip6: Mutex<Vec<(Ipv6Addr, SoftwareInfo)>>,
}

impl AuthorityImpl {
    fn create_records(&self, rng: &mut impl Rng) -> Option<BTreeMap<RrKey, Arc<RecordSet>>> {
        let new_serial = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("valid time expected")
            .as_secs() as u32;
        let old_serial = self.serial.swap(new_serial);
        if old_serial == new_serial {
            return None;
        }

        let ipv4_addrs = self.select_addresses(
            &self.ip4.lock().expect("mutex must be valid (refresh ipv4)"),
            MAX_IPV4_RECORDS,
            rng,
        );

        let ipv6_addrs = self.select_addresses(
            &self.ip6.lock().expect("mutex must be valid (refresh ipv6)"),
            MAX_IPV6_RECORDS,
            rng,
        );

        let mut new_records = BTreeMap::new();

        if let Some(mbox) = self.mbox.as_ref() {
            let mut soa_rec = RecordSet::with_ttl(self.host.clone(), RecordType::SOA, TTL_SOA);
            soa_rec.add_rdata(RData::SOA(SOA::new(
                self.host.clone(),
                mbox.clone(),
                new_serial,
                SOA_REFRESH,
                SOA_RETRY,
                SOA_EXPIRE,
                SOA_MINIMUM,
            )));
            new_records.insert(
                RrKey::new(soa_rec.name().clone().into(), soa_rec.record_type()),
                Arc::new(soa_rec),
            );
        }

        if let Some(nameserver) = self.nameserver.as_ref() {
            let mut ns_rec = RecordSet::with_ttl(self.host.clone(), RecordType::NS, TTL_NS);
            ns_rec.add_rdata(RData::NS(NS(nameserver.clone())));
            new_records.insert(
                RrKey::new(ns_rec.name().clone().into(), ns_rec.record_type()),
                Arc::new(ns_rec),
            );
        }

        // A records
        let mut ipv4_rec = RecordSet::with_ttl(self.host.clone(), RecordType::A, TTL_IP);
        for ip in ipv4_addrs {
            ipv4_rec.add_rdata(RData::A(ip.into()));
        }
        new_records.insert(
            RrKey::new(ipv4_rec.name().clone().into(), ipv4_rec.record_type()),
            Arc::new(ipv4_rec),
        );

        // AAAA records
        let mut ipv6_rec = RecordSet::with_ttl(self.host.clone(), RecordType::AAAA, TTL_IP);
        for ip in ipv6_addrs {
            ipv6_rec.add_rdata(RData::AAAA(ip.into()));
        }
        new_records.insert(
            RrKey::new(ipv6_rec.name().clone().into(), ipv6_rec.record_type()),
            Arc::new(ipv6_rec),
        );

        Some(new_records)
    }

    async fn refresh(&self) {
        let new_records = self.create_records(&mut make_pseudo_rng());
        log::trace!("Refreshing, new records = {new_records:#?}");

        if let Some(new_records) = new_records {
            *self.inner.records_mut().await = new_records;
        }
    }

    fn select_addresses<Addr: Clone>(
        &self,
        addrs: &[(Addr, SoftwareInfo)],
        count: usize,
        rng: &mut impl Rng,
    ) -> Vec<Addr> {
        let same_software_info = SoftwareInfo::current(&self.chain_config);

        let mut same_version_addrs = addrs
            .iter()
            .filter_map(|(addr, software_info)| {
                (*software_info == same_software_info).then(|| addr.clone())
            })
            .choose_multiple(rng, count);
        same_version_addrs.shuffle(rng);

        let mut other_version_addrs = addrs
            .iter()
            .filter_map(|(addr, software_info)| {
                (*software_info != same_software_info).then(|| addr.clone())
            })
            .choose_multiple(rng, count);
        other_version_addrs.shuffle(rng);

        let same_version_addrs_preferred_count =
            (count as f64 * SAME_SOFTWARE_VERSION_PEERS_RATIO) as usize;

        let mut result = Vec::with_capacity(count);

        // First take the required number of same-version addresses.
        let addr_count_to_take =
            std::cmp::min(same_version_addrs_preferred_count, same_version_addrs.len());
        result.extend(same_version_addrs.drain(..addr_count_to_take));

        // Fill the rest with other-version addresses.
        let addr_count_to_take = std::cmp::min(count - result.len(), other_version_addrs.len());
        result.extend(other_version_addrs.drain(..addr_count_to_take));

        // If there is still some space left, fill it with same-version addresses, if any.
        if result.len() < count {
            let addr_count_to_take = std::cmp::min(count - result.len(), same_version_addrs.len());
            result.extend(same_version_addrs.drain(..addr_count_to_take));
        }

        result
    }
}

#[async_trait::async_trait]
impl Authority for AuthorityImpl {
    type Lookup = AuthLookup;

    fn zone_type(&self) -> ZoneType {
        self.inner.zone_type()
    }

    fn is_axfr_allowed(&self) -> bool {
        self.inner.is_axfr_allowed()
    }

    async fn update(&self, update: &MessageRequest) -> UpdateResult<bool> {
        self.inner.update(update).await
    }

    fn origin(&self) -> &LowerName {
        self.inner.origin()
    }

    async fn lookup(
        &self,
        name: &LowerName,
        query_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        log::trace!(
            "In lookup for {:?}, query_type = {:?}, lookup_options = {:?}",
            name,
            query_type,
            lookup_options
        );
        self.refresh().await;
        self.inner.lookup(name, query_type, lookup_options).await
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        log::trace!(
            "In search, src = {:?}, protocol = {:?}, header = {:?}, query = {:?}, lookup_options = {:?}",
            request_info.src,
            request_info.protocol,
            request_info.header,
            request_info.query,
            lookup_options
        );
        self.refresh().await;
        self.inner.search(request_info, lookup_options).await
    }

    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        self.inner.get_nsec_records(name, lookup_options).await
    }
}

fn handle_command(auth: &AuthorityImpl, command: DnsServerCommand) {
    match command {
        DnsServerCommand::AddAddress(IpAddr::V4(ip), software_version) => {
            log::debug!("Adding address {ip}");
            auth.ip4
                .lock()
                .expect("mutex must be valid (add ipv4)")
                .push((ip, software_version));
        }
        DnsServerCommand::AddAddress(IpAddr::V6(ip), software_version) => {
            log::debug!("Adding address {ip}");
            auth.ip6
                .lock()
                .expect("mutex must be valid (add ipv6)")
                .push((ip, software_version));
        }
        DnsServerCommand::DelAddress(IpAddr::V4(ip)) => {
            log::debug!("Deleting address {ip}");
            auth.ip4
                .lock()
                .expect("mutex must be valid (remove ipv4)")
                .retain(|(addr, _)| *addr != ip);
        }
        DnsServerCommand::DelAddress(IpAddr::V6(ip)) => {
            log::debug!("Deleting address {ip}");
            auth.ip6
                .lock()
                .expect("mutex must be valid (remove ipv6)")
                .retain(|(addr, _)| *addr != ip);
        }
    };
}

#[cfg(test)]
mod tests;
