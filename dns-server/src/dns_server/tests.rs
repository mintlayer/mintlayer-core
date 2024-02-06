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
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use crypto::random::{Rng, SliceRandom};
use p2p::testing_utils::TestAddressMaker;
use trust_dns_client::rr::{Name, RData, RecordType};
use trust_dns_server::{
    authority::{Authority, ZoneType},
    store::in_memory::InMemoryAuthority,
};

use common::{
    chain::{self, ChainConfig},
    primitives::semver::SemVer,
};
use test_utils::{assert_matches_return_val, random::Seed};

use crate::{
    crawler_p2p::crawler::address_data::SoftwareInfo,
    dns_server::{
        handle_command, AuthorityImpl, DnsServerCommand, MAX_IPV4_RECORDS, MAX_IPV6_RECORDS,
        SAME_SOFTWARE_VERSION_PEERS_RATIO,
    },
};

#[tokio::test]
async fn dns_server_basic() {
    let chain_config = Arc::new(chain::config::create_testnet());
    let host: Name = "seed.mintlayer.org.".parse().unwrap();
    let nameserver = Some("ns.mintlayer.org.".parse().unwrap());
    let mbox = Some("admin.mintlayer.org.".parse().unwrap());
    let soft_info = SoftwareInfo {
        user_agent: "foo1".try_into().unwrap(),
        version: SemVer::new(1, 2, 3),
    };

    let inner = InMemoryAuthority::empty(host.clone(), ZoneType::Primary, false);

    let auth = AuthorityImpl {
        chain_config,
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
    handle_command(
        &auth,
        DnsServerCommand::AddAddress(ip1.into(), soft_info.clone()),
    );
    handle_command(&auth, DnsServerCommand::AddAddress(ip2.into(), soft_info));
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
    assert_eq!(result_a[0].data(), Some(&RData::A(ip1.into())));

    let result_aaaa = auth
        .lookup(&host.clone().into(), RecordType::AAAA, Default::default())
        .await
        .unwrap()
        .unwrap_records()
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(result_aaaa.len(), 1);
    assert_eq!(result_aaaa[0].data(), Some(&RData::AAAA(ip2.into())));

    handle_command(&auth, DnsServerCommand::DelAddress(ip1.into()));
    handle_command(&auth, DnsServerCommand::DelAddress(ip2.into()));
    assert_eq!(auth.ip4.lock().unwrap().len(), 0);
    assert_eq!(auth.ip6.lock().unwrap().len(), 0);
}

mod same_software_version_addr_selection_test {
    use super::*;

    fn test_impl(
        chain_config: Arc<ChainConfig>,
        addr_map: &BTreeMap<IpAddr, SoftwareInfo>,
        expected_same_soft_version_v4_addr_count: usize,
        expected_same_soft_version_v6_addr_count: usize,
        rng: &mut impl Rng,
    ) {
        let addrs = {
            let mut addrs = addr_map.keys().copied().collect::<Vec<_>>();
            addrs.shuffle(rng);
            addrs
        };

        let host: Name = "seed.mintlayer.org.".parse().unwrap();
        let cur_soft_info = SoftwareInfo::current(&chain_config);

        let inner = InMemoryAuthority::empty(host.clone(), ZoneType::Primary, false);
        let auth = AuthorityImpl {
            chain_config: Arc::clone(&chain_config),
            serial: Default::default(),
            host: host.clone(),
            // Prevent the creation of SOA and NS records, for simplicity.
            nameserver: None,
            mbox: None,
            inner,
            ip4: Default::default(),
            ip6: Default::default(),
        };

        for addr in &addrs {
            handle_command(
                &auth,
                DnsServerCommand::AddAddress(*addr, addr_map.get(addr).unwrap().clone()),
            );
        }

        let records = auth.create_records(rng).unwrap().into_iter().collect::<Vec<_>>();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].0.record_type, RecordType::A);
        assert_eq!(records[1].0.record_type, RecordType::AAAA);

        let selected_v4_addrs = records[0]
            .1
            .records_without_rrsigs()
            .map(|rec| assert_matches_return_val!(rec.data(), Some(&RData::A(a)), a.0))
            .collect::<Vec<_>>();
        assert_eq!(selected_v4_addrs.len(), MAX_IPV4_RECORDS);
        let same_soft_version_addr_count = selected_v4_addrs
            .iter()
            .filter(|addr| *addr_map.get(&(**addr).into()).unwrap() == cur_soft_info)
            .count();
        assert_eq!(
            same_soft_version_addr_count,
            expected_same_soft_version_v4_addr_count
        );

        let selected_v6_addrs = records[1]
            .1
            .records_without_rrsigs()
            .map(|rec| assert_matches_return_val!(rec.data(), Some(&RData::AAAA(a)), a.0))
            .collect::<Vec<_>>();
        assert_eq!(selected_v6_addrs.len(), MAX_IPV6_RECORDS);
        let same_soft_version_addr_count = selected_v6_addrs
            .iter()
            .filter(|addr| *addr_map.get(&(**addr).into()).unwrap() == cur_soft_info)
            .count();
        assert_eq!(
            same_soft_version_addr_count,
            expected_same_soft_version_v6_addr_count
        );
    }

    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn test_normal(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(chain::config::create_testnet());

        let v4_addr_count = 100;
        let v6_addr_count = 100;
        assert!(v4_addr_count > 2 * MAX_IPV4_RECORDS);
        assert!(v6_addr_count > 2 * MAX_IPV6_RECORDS);

        let v4_addrs = TestAddressMaker::new_distinct_random_ipv4_addrs(v4_addr_count, &mut rng);
        let v6_addrs = TestAddressMaker::new_distinct_random_ipv6_addrs(v6_addr_count, &mut rng);

        let addr_map = make_test_software_infos_from_indices(
            v4_addrs.into_iter().map(IpAddr::V4).chain(v6_addrs.into_iter().map(IpAddr::V6)),
            &chain_config,
            &mut rng,
        );

        let expected_same_soft_version_v4_addr_count =
            (MAX_IPV4_RECORDS as f64 * SAME_SOFTWARE_VERSION_PEERS_RATIO) as usize;
        let expected_same_soft_version_v6_addr_count =
            (MAX_IPV6_RECORDS as f64 * SAME_SOFTWARE_VERSION_PEERS_RATIO) as usize;
        test_impl(
            chain_config,
            &addr_map,
            expected_same_soft_version_v4_addr_count,
            expected_same_soft_version_v6_addr_count,
            &mut rng,
        );
    }

    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn test_all_versions_are_current(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(chain::config::create_testnet());
        let cur_soft_info = SoftwareInfo::current(&chain_config);

        let v4_addr_count = 100;
        let v6_addr_count = 100;
        assert!(v4_addr_count > 2 * MAX_IPV4_RECORDS);
        assert!(v6_addr_count > 2 * MAX_IPV6_RECORDS);

        let v4_addrs = TestAddressMaker::new_distinct_random_ipv4_addrs(v4_addr_count, &mut rng);
        let v6_addrs = TestAddressMaker::new_distinct_random_ipv6_addrs(v6_addr_count, &mut rng);

        let addr_map = v4_addrs
            .into_iter()
            .map(IpAddr::V4)
            .chain(v6_addrs.into_iter().map(IpAddr::V6))
            .map(|addr| (addr, cur_soft_info.clone()))
            .collect::<BTreeMap<_, _>>();

        test_impl(
            chain_config,
            &addr_map,
            MAX_IPV4_RECORDS,
            MAX_IPV6_RECORDS,
            &mut rng,
        );
    }

    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn test_all_versions_are_other(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(chain::config::create_testnet());

        let v4_addr_count = 100;
        let v6_addr_count = 100;
        assert!(v4_addr_count > 2 * MAX_IPV4_RECORDS);
        assert!(v6_addr_count > 2 * MAX_IPV6_RECORDS);

        let v4_addrs = TestAddressMaker::new_distinct_random_ipv4_addrs(v4_addr_count, &mut rng);
        let v6_addrs = TestAddressMaker::new_distinct_random_ipv6_addrs(v6_addr_count, &mut rng);

        let addr_map = v4_addrs
            .into_iter()
            .map(IpAddr::V4)
            .chain(v6_addrs.into_iter().map(IpAddr::V6))
            .map(|addr| (addr, make_random_software_info(&mut rng)))
            .collect::<BTreeMap<_, _>>();

        test_impl(chain_config, &addr_map, 0, 0, &mut rng);
    }

    fn make_random_software_info(rng: &mut impl Rng) -> SoftwareInfo {
        SoftwareInfo {
            user_agent: "bogus".try_into().unwrap(),
            version: SemVer::new(rng.gen(), rng.gen(), rng.gen()),
        }
    }

    fn make_test_software_info_from_index(
        idx: usize,
        chain_config: &ChainConfig,
        rng: &mut impl Rng,
    ) -> SoftwareInfo {
        if idx % 2 == 0 {
            SoftwareInfo::current(chain_config)
        } else {
            make_random_software_info(rng)
        }
    }

    fn make_test_software_infos_from_indices<Addr: Clone + Ord>(
        addrs: impl Iterator<Item = Addr>,
        chain_config: &ChainConfig,
        rng: &mut impl Rng,
    ) -> BTreeMap<Addr, SoftwareInfo> {
        addrs
            .enumerate()
            .map(|(idx, addr)| {
                let soft_info = make_test_software_info_from_index(idx, chain_config, rng);
                (addr.clone(), soft_info)
            })
            .collect::<BTreeMap<_, _>>()
    }
}
