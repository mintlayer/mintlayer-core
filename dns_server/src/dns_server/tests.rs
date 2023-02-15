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

use std::net::{Ipv4Addr, Ipv6Addr};

use trust_dns_client::rr::{Name, RData, RecordType};
use trust_dns_server::{
    authority::{Authority, ZoneType},
    store::in_memory::InMemoryAuthority,
};

use crate::dns_server::{handle_command, AuthorityImpl, ServerCommands};

#[tokio::test]
async fn dns_server_basic() {
    let host: Name = "seed.mintlayer.org.".parse().unwrap();
    let nameserver = Some("ns.mintlayer.org.".parse().unwrap());
    let mbox = Some("admin.mintlayer.org.".parse().unwrap());

    let inner = InMemoryAuthority::empty(host.clone(), ZoneType::Primary, false);

    let auth = AuthorityImpl {
        serial: Default::default(),
        host: host.clone(),
        nameserver,
        mbox,
        inner,
        ip4: Default::default(),
        ip6: Default::default(),
    };

    let ip1: Ipv4Addr = "1.2.3.4".parse().unwrap();
    let ip2: Ipv6Addr = "2a00::1".parse().unwrap();
    handle_command(&auth, ServerCommands::AddAddress(ip1.into()));
    handle_command(&auth, ServerCommands::AddAddress(ip2.into()));
    assert_eq!(auth.ip4.lock().unwrap().len(), 1);
    assert_eq!(auth.ip6.lock().unwrap().len(), 1);

    let result_a = auth
        .lookup(&host.clone().into(), RecordType::A, Default::default())
        .await
        .unwrap()
        .unwrap_records()
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(result_a.len(), 1);
    assert_eq!(result_a[0].data(), Some(&RData::A(ip1)));

    let result_aaaa = auth
        .lookup(&host.clone().into(), RecordType::AAAA, Default::default())
        .await
        .unwrap()
        .unwrap_records()
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(result_aaaa.len(), 1);
    assert_eq!(result_aaaa[0].data(), Some(&RData::AAAA(ip2)));

    handle_command(&auth, ServerCommands::DelAddress(ip1.into()));
    handle_command(&auth, ServerCommands::DelAddress(ip2.into()));
    assert_eq!(auth.ip4.lock().unwrap().len(), 0);
    assert_eq!(auth.ip6.lock().unwrap().len(), 0);
}
