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
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
};

use common::{chain::ChainConfig, primitives::per_thousand::PerThousand};
use futures::never::Never;
use hickory_client::{
    proto::rr::{LowerName, RrKey},
    rr::{
        rdata::{NS, SOA},
        Name, RData, RecordSet, RecordType,
    },
};
use hickory_server::{
    authority::{
        AuthLookup, Authority, Catalog, LookupError, LookupOptions, MessageRequest, UpdateResult,
        ZoneType,
    },
    server::RequestInfo,
    store::in_memory::InMemoryAuthority,
    ServerFuture,
};
use itertools::Itertools;
use logging::log;
use randomness::{make_pseudo_rng, Rng, SliceRandom};
use tokio::{net::UdpSocket, sync::mpsc};
use utils::{atomics::RelaxedAtomicU32, make_config_setting};

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
const TTL_IP: u32 = 3600;
const TTL_NS: u32 = 21600;
const TTL_SOA: u32 = 21600;

make_config_setting!(MaxIpv4RecordsCount, usize, 24);
make_config_setting!(MaxIpv6RecordsCount, usize, 14);
make_config_setting!(
    MinSameSoftwareVersionNodesRatio,
    PerThousand,
    PerThousand::new(950).expect("Must be a valid per-thousand")
);

impl DnsServer {
    pub async fn new(
        config: Arc<DnsServerConfig>,
        chain_config: Arc<ChainConfig>,
        cmd_rx: mpsc::UnboundedReceiver<DnsServerCommand>,
    ) -> crate::Result<Self> {
        let inner = InMemoryAuthority::empty(config.host.clone(), ZoneType::Primary, false);

        let auth = Arc::new(AuthorityImpl {
            config: AuthorityImplConfig::from_dns_server_config(&config),
            chain_config,
            serial: Default::default(),
            inner,
            ipv4_addrs: Default::default(),
            ipv6_addrs: Default::default(),
        });

        let mut catalog = Catalog::new();

        catalog.upsert(config.host.clone().into(), Box::new(Arc::clone(&auth)));

        let mut server = ServerFuture::new(catalog);

        for bind_addr in config.bind_addr.iter() {
            let udp_socket = UdpSocket::bind(bind_addr).await?;
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
            mut server,
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

struct AuthorityImplConfig {
    pub host: Name,
    pub nameserver: Option<Name>,
    pub mbox: Option<Name>,
    pub min_same_software_version_nodes_ratio: PerThousand,

    /// Maximum number of IPv4 addresses in result,
    pub max_ipv4_records: MaxIpv4RecordsCount,

    /// Maximum number of IPv6 addresses in result,
    pub max_ipv6_records: MaxIpv6RecordsCount,
}

impl AuthorityImplConfig {
    pub fn from_dns_server_config(server_config: &DnsServerConfig) -> Self {
        Self {
            host: server_config.host.clone(),
            nameserver: server_config.nameserver.clone(),
            mbox: server_config.mbox.clone(),
            min_same_software_version_nodes_ratio: server_config
                .min_same_software_version_nodes_ratio,
            max_ipv4_records: Default::default(),
            max_ipv6_records: Default::default(),
        }
    }
}

/// Wrapper for InMemoryAuthority that selects random addresses every second
struct AuthorityImpl {
    chain_config: Arc<ChainConfig>,
    config: AuthorityImplConfig,
    serial: RelaxedAtomicU32,
    inner: InMemoryAuthority,
    ipv4_addrs: Mutex<BTreeMap<Ipv4Addr, SoftwareInfo>>,
    ipv6_addrs: Mutex<BTreeMap<Ipv6Addr, SoftwareInfo>>,
}

impl AuthorityImpl {
    fn addr_info_for_logging<Addr: Clone + Ord>(
        addrs_to_include: &[Addr],
        all_addrs: &BTreeMap<Addr, SoftwareInfo>,
    ) -> BTreeMap<Addr, String> {
        addrs_to_include
            .iter()
            .map(|addr| {
                let software_info = all_addrs.get(addr).expect("Address must be known");
                let software_info_str =
                    format!("{}-{}", software_info.user_agent, software_info.version);
                (addr.clone(), software_info_str)
            })
            .collect()
    }

    fn create_records(&self, rng: &mut impl Rng) -> Option<BTreeMap<RrKey, Arc<RecordSet>>> {
        let new_serial = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("valid time expected")
            .as_secs() as u32;
        let old_serial = self.serial.swap(new_serial);
        if old_serial == new_serial {
            return None;
        }

        log::debug!("Creating new records");

        let selected_ipv4_addrs = {
            let all_addrs = &self.ipv4_addrs.lock().expect("mutex must be valid (ipv4_addrs)");
            let selected_addrs =
                self.select_addresses(all_addrs, *self.config.max_ipv4_records, rng);
            log::trace!(
                "Selected v4 addresses: {:?}",
                Self::addr_info_for_logging(&selected_addrs, all_addrs)
            );
            selected_addrs
        };

        let selected_ipv6_addrs = {
            let all_addrs = &self.ipv6_addrs.lock().expect("mutex must be valid (ipv6_addrs)");
            let selected_addrs =
                self.select_addresses(all_addrs, *self.config.max_ipv6_records, rng);
            log::trace!(
                "Selected v6 addresses: {:?}",
                Self::addr_info_for_logging(&selected_addrs, all_addrs)
            );
            selected_addrs
        };

        let mut new_records = BTreeMap::new();

        if let Some(mbox) = self.config.mbox.as_ref() {
            let mut soa_rec =
                RecordSet::with_ttl(self.config.host.clone(), RecordType::SOA, TTL_SOA);
            soa_rec.add_rdata(RData::SOA(SOA::new(
                self.config.host.clone(),
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

        if let Some(nameserver) = self.config.nameserver.as_ref() {
            let mut ns_rec = RecordSet::with_ttl(self.config.host.clone(), RecordType::NS, TTL_NS);
            ns_rec.add_rdata(RData::NS(NS(nameserver.clone())));
            new_records.insert(
                RrKey::new(ns_rec.name().clone().into(), ns_rec.record_type()),
                Arc::new(ns_rec),
            );
        }

        // A records
        let mut ipv4_rec = RecordSet::with_ttl(self.config.host.clone(), RecordType::A, TTL_IP);
        for ip in selected_ipv4_addrs {
            ipv4_rec.add_rdata(RData::A(ip.into()));
        }
        new_records.insert(
            RrKey::new(ipv4_rec.name().clone().into(), ipv4_rec.record_type()),
            Arc::new(ipv4_rec),
        );

        // AAAA records
        let mut ipv6_rec = RecordSet::with_ttl(self.config.host.clone(), RecordType::AAAA, TTL_IP);
        for ip in selected_ipv6_addrs {
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

        if let Some(new_records) = new_records {
            *self.inner.records_mut().await = new_records;
        }
    }

    fn select_addresses<Addr: Clone>(
        &self,
        addrs: &BTreeMap<Addr, SoftwareInfo>,
        count: usize,
        rng: &mut impl Rng,
    ) -> Vec<Addr> {
        let same_software_info = SoftwareInfo::current(&self.chain_config);

        let (same_version_addrs, other_version_addrs): (Vec<_>, Vec<_>) =
            addrs.iter().partition_map(|(addr, software_info)| {
                if *software_info == same_software_info {
                    itertools::Either::Left(addr.clone())
                } else {
                    itertools::Either::Right(addr.clone())
                }
            });

        let mut selected_same_version_addrs =
            same_version_addrs.choose_multiple(rng, count).cloned().collect::<Vec<_>>();
        selected_same_version_addrs.shuffle(rng);

        let mut selected_other_version_addrs =
            other_version_addrs.choose_multiple(rng, count).cloned().collect::<Vec<_>>();
        selected_other_version_addrs.shuffle(rng);

        #[allow(clippy::float_arithmetic)]
        let same_version_addrs_preferred_count = {
            let min_same_software_version_nodes_ratio =
                self.config.min_same_software_version_nodes_ratio.as_f64();
            let current_same_software_version_nodes_ratio =
                same_version_addrs.len() as f64 / addrs.len() as f64;
            let required_same_software_version_nodes_ratio = f64::max(
                min_same_software_version_nodes_ratio,
                current_same_software_version_nodes_ratio,
            );

            (count as f64 * required_same_software_version_nodes_ratio).round() as usize
        };

        let mut result = Vec::with_capacity(count);

        // First take the required number of same-version addresses.
        let addr_count_to_take = std::cmp::min(
            same_version_addrs_preferred_count,
            selected_same_version_addrs.len(),
        );
        result.extend(selected_same_version_addrs.drain(..addr_count_to_take));

        // Fill the rest with other-version addresses.
        let addr_count_to_take =
            std::cmp::min(count - result.len(), selected_other_version_addrs.len());
        result.extend(selected_other_version_addrs.drain(..addr_count_to_take));

        // If there is still some space left, fill it with same-version addresses, if any.
        if result.len() < count {
            let addr_count_to_take =
                std::cmp::min(count - result.len(), selected_same_version_addrs.len());
            result.extend(selected_same_version_addrs.drain(..addr_count_to_take));
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
            auth.ipv4_addrs
                .lock()
                .expect("mutex must be valid (add ipv4)")
                .insert(ip, software_version);
        }
        DnsServerCommand::AddAddress(IpAddr::V6(ip), software_version) => {
            log::debug!("Adding address {ip}");
            auth.ipv6_addrs
                .lock()
                .expect("mutex must be valid (add ipv6)")
                .insert(ip, software_version);
        }
        DnsServerCommand::DelAddress(IpAddr::V4(ip)) => {
            log::debug!("Deleting address {ip}");
            auth.ipv4_addrs.lock().expect("mutex must be valid (remove ipv4)").remove(&ip);
        }
        DnsServerCommand::DelAddress(IpAddr::V6(ip)) => {
            log::debug!("Deleting address {ip}");
            auth.ipv6_addrs.lock().expect("mutex must be valid (remove ipv6)").remove(&ip);
        }
    };
}

#[cfg(test)]
mod tests;
