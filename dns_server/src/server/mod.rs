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

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
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

#[derive(Debug)]
pub enum ServerCommands {
    AddAddress(IpAddr),

    DelAddress(IpAddr),
}

pub struct Server {
    auth: Arc<AuthorityImpl>,

    server: ServerFuture<Catalog>,

    command_tx: mpsc::UnboundedReceiver<ServerCommands>,
}

// Same values as in `https://github.com/sipa/bitcoin-seeder/blob/master/dns.cpp`
const DEFAULT_REFRESH: i32 = 604800;
const DEFAULT_RETRY: i32 = 86400;
const DEFAULT_EXPIRE: i32 = 2592000;
const DEFAULT_MINIMUM: u32 = 604800;

const MAX_IPV4_RECORDS: usize = 24;
const MAX_IPV6_RECORDS: usize = 14;

impl Server {
    pub async fn new(
        config: Arc<DnsServerConfig>,
        command_tx: mpsc::UnboundedReceiver<ServerCommands>,
    ) -> Result<Self, DnsServerError> {
        let host = Name::from_str(&config.host)?;
        let ns = Name::from_str(&config.ns)?;
        let mbox = Name::from_str(&config.mbox)?;

        let inner = InMemoryAuthority::empty(host.clone(), ZoneType::Primary, false);

        let auth = Arc::new(AuthorityImpl {
            serial: Default::default(),
            host,
            ns,
            mbox,
            inner,
            ip4: Default::default(),
            ip6: Default::default(),
        });

        let mut catalog = Catalog::new();

        catalog.upsert(
            LowerName::from_str(&config.host)?,
            Box::new(Arc::clone(&auth)),
        );

        let mut server = ServerFuture::new(catalog);

        for bind_addr in config.bind_addr.iter() {
            let socket_addr: SocketAddr = bind_addr.parse()?;
            let udp_socket = UdpSocket::bind(socket_addr).await?;
            server.register_socket(udp_socket);
        }

        Ok(Self {
            auth,
            server,
            command_tx,
        })
    }

    pub async fn run(self) -> Result<void::Void, DnsServerError> {
        let Server {
            auth,
            server,
            mut command_tx,
        } = self;

        tokio::spawn(async move {
            while let Some(command) = command_tx.recv().await {
                handle_command(&auth, command);
            }
        });

        server.block_until_done().await?;

        Err(DnsServerError::Other(
            "trust_dns_server terminated unexpectedly",
        ))
    }
}

struct AuthorityImpl {
    serial: AtomicU32,
    host: Name,
    ns: Name,
    mbox: Name,
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
            .expect("mutex must be valid")
            .choose_multiple(&mut make_pseudo_rng(), MAX_IPV4_RECORDS)
            .cloned()
            .collect::<Vec<_>>();

        let ipv6 = self
            .ip6
            .lock()
            .expect("mutex must be valid")
            .choose_multiple(&mut make_pseudo_rng(), MAX_IPV6_RECORDS)
            .cloned()
            .collect::<Vec<_>>();

        let mut soa_rec = RecordSet::new(&self.host, RecordType::SOA, 0);
        let mut ns_rec = RecordSet::new(&self.host, RecordType::NS, 0);
        let mut ipv4_rec = RecordSet::new(&self.host, RecordType::A, 0);
        let mut ipv6_rec = RecordSet::new(&self.host, RecordType::AAAA, 0);

        soa_rec.add_rdata(RData::SOA(SOA::new(
            self.host.clone(),
            self.mbox.clone(),
            new_serial,
            DEFAULT_REFRESH,
            DEFAULT_RETRY,
            DEFAULT_EXPIRE,
            DEFAULT_MINIMUM,
        )));

        ns_rec.add_rdata(RData::NS(self.ns.clone()));

        for ip in ipv4 {
            ipv4_rec.add_rdata(RData::A(ip));
        }

        for ip in ipv6 {
            ipv6_rec.add_rdata(RData::AAAA(ip));
        }

        let mut new_records = BTreeMap::new();
        new_records.insert(
            RrKey::new(soa_rec.name().clone().into(), soa_rec.record_type()),
            Arc::new(soa_rec),
        );
        new_records.insert(
            RrKey::new(ns_rec.name().clone().into(), ns_rec.record_type()),
            Arc::new(ns_rec),
        );
        new_records.insert(
            RrKey::new(ipv4_rec.name().clone().into(), ipv4_rec.record_type()),
            Arc::new(ipv4_rec),
        );
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

fn handle_command(auth: &AuthorityImpl, command: ServerCommands) {
    match command {
        ServerCommands::AddAddress(IpAddr::V4(ip)) => {
            auth.ip4.lock().expect("mutex must be valid").push(ip);
        }
        ServerCommands::AddAddress(IpAddr::V6(ip)) => {
            auth.ip6.lock().expect("mutex must be valid").push(ip);
        }
        ServerCommands::DelAddress(IpAddr::V4(ip)) => {
            auth.ip4.lock().expect("mutex must be valid").retain(|val| *val != ip);
        }
        ServerCommands::DelAddress(IpAddr::V6(ip)) => {
            auth.ip6.lock().expect("mutex must be valid").retain(|val| *val != ip);
        }
    };
}
