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
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
};

use crypto::random::{make_pseudo_rng, SliceRandom};
use tokio::{net::UdpSocket, sync::mpsc};
use trust_dns_client::rr::{rdata::SOA, LowerName, Name, RData, RecordSet, RecordType, RrKey};
use trust_dns_server::{
    authority::{
        AuthLookup, Authority, Catalog, LookupError, LookupOptions, MessageRequest, UpdateResult,
        ZoneType,
    },
    server::RequestInfo,
    store::in_memory::InMemoryAuthority,
    ServerFuture,
};

use crate::{config::DnsServerConfig, error::DnsServerError};

#[derive(Debug, PartialEq, Eq)]
pub enum DnsServerCommand {
    AddAddress(IpAddr),

    DelAddress(IpAddr),
}

pub struct DnsServer {
    auth: Arc<AuthorityImpl>,

    server: ServerFuture<Catalog>,

    cmd_rx: mpsc::UnboundedReceiver<DnsServerCommand>,
}

// Same values as in `https://github.com/sipa/bitcoin-seeder/blob/3ef602de83a76bc95a06867d4bfc239f13992140/dns.cpp`
const SOA_REFRESH: i32 = 604800;
const SOA_RETRY: i32 = 86400;
const SOA_EXPIRE: i32 = 2592000;
const SOA_MINIMUM: u32 = 604800;

// Same values as in `https://github.com/sipa/bitcoin-seeder/blob/3ef602de83a76bc95a06867d4bfc239f13992140/dns.cpp`
const TTL_IP: u32 = 3600;
const TTL_NS: u32 = 21600;
const TTL_SOA: u32 = 21600;

// Maximum number of IPv4 addresses in result
const MAX_IPV4_RECORDS: usize = 24;

// Maximum number of IPv6 addresses in result
const MAX_IPV6_RECORDS: usize = 14;

impl DnsServer {
    pub async fn new(
        config: Arc<DnsServerConfig>,
        cmd_rx: mpsc::UnboundedReceiver<DnsServerCommand>,
    ) -> Result<Self, DnsServerError> {
        let inner = InMemoryAuthority::empty(config.host.clone(), ZoneType::Primary, false);

        let auth = Arc::new(AuthorityImpl {
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

    pub async fn run(self) -> Result<void::Void, DnsServerError> {
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
    serial: AtomicU32,
    host: Name,
    nameserver: Option<Name>,
    mbox: Option<Name>,
    inner: InMemoryAuthority,
    ip4: Mutex<Vec<Ipv4Addr>>,
    ip6: Mutex<Vec<Ipv6Addr>>,
}

impl AuthorityImpl {
    async fn refresh(&self) {
        let new_serial = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("valid time expected")
            .as_secs() as u32;
        let old_serial = self.serial.swap(new_serial, Ordering::Relaxed);
        if old_serial == new_serial {
            return;
        }

        let ipv4 = self
            .ip4
            .lock()
            .expect("mutex must be valid (refresh ipv4)")
            .choose_multiple(&mut make_pseudo_rng(), MAX_IPV4_RECORDS)
            .cloned()
            .collect::<Vec<_>>();

        let ipv6 = self
            .ip6
            .lock()
            .expect("mutex must be valid (refresh ipv6)")
            .choose_multiple(&mut make_pseudo_rng(), MAX_IPV6_RECORDS)
            .cloned()
            .collect::<Vec<_>>();

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
            ns_rec.add_rdata(RData::NS(nameserver.clone()));
            new_records.insert(
                RrKey::new(ns_rec.name().clone().into(), ns_rec.record_type()),
                Arc::new(ns_rec),
            );
        }

        // A records
        let mut ipv4_rec = RecordSet::with_ttl(self.host.clone(), RecordType::A, TTL_IP);
        for ip in ipv4 {
            ipv4_rec.add_rdata(RData::A(ip));
        }
        new_records.insert(
            RrKey::new(ipv4_rec.name().clone().into(), ipv4_rec.record_type()),
            Arc::new(ipv4_rec),
        );

        // AAAA records
        let mut ipv6_rec = RecordSet::with_ttl(self.host.clone(), RecordType::AAAA, TTL_IP);
        for ip in ipv6 {
            ipv6_rec.add_rdata(RData::AAAA(ip));
        }
        new_records.insert(
            RrKey::new(ipv6_rec.name().clone().into(), ipv6_rec.record_type()),
            Arc::new(ipv6_rec),
        );

        *self.inner.records_mut().await = new_records;
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
        self.refresh().await;
        self.inner.lookup(name, query_type, lookup_options).await
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
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
        DnsServerCommand::AddAddress(IpAddr::V4(ip)) => {
            auth.ip4.lock().expect("mutex must be valid (add ipv4)").push(ip);
        }
        DnsServerCommand::AddAddress(IpAddr::V6(ip)) => {
            auth.ip6.lock().expect("mutex must be valid (add ipv6)").push(ip);
        }
        DnsServerCommand::DelAddress(IpAddr::V4(ip)) => {
            auth.ip4
                .lock()
                .expect("mutex must be valid (remove ipv4)")
                .retain(|val| *val != ip);
        }
        DnsServerCommand::DelAddress(IpAddr::V6(ip)) => {
            auth.ip6
                .lock()
                .expect("mutex must be valid (remove ipv6)")
                .retain(|val| *val != ip);
        }
    };
}

#[cfg(test)]
mod tests;
