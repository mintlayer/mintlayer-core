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

use trust_dns_client::rr::{RData, RecordType};
use trust_dns_server::{
    authority::{Authority, ZoneType},
    store::in_memory::InMemoryAuthority,
};

use common::{
    chain::{self, ChainConfig},
    primitives::{per_thousand::PerThousand, semver::SemVer},
};
use p2p::testing_utils::TestAddressMaker;
use randomness::{Rng, SliceRandom};
use test_utils::{assert_matches_return_val, merge_btree_maps, random::Seed};

use crate::{
    crawler_p2p::crawler::address_data::SoftwareInfo,
    dns_server::{handle_command, AuthorityImpl, DnsServerCommand},
};

use super::{AuthorityImplConfig, MinSameSoftwareVersionNodesRatio};

fn create_test_config() -> AuthorityImplConfig {
    AuthorityImplConfig {
        host: "seed.mintlayer.org.".parse().unwrap(),
        nameserver: Some("ns.mintlayer.org.".parse().unwrap()),
        mbox: Some("admin.mintlayer.org.".parse().unwrap()),
        min_same_software_version_nodes_ratio: *MinSameSoftwareVersionNodesRatio::default(),
        max_ipv4_records: Default::default(),
        max_ipv6_records: Default::default(),
    }
}

#[tokio::test]
async fn dns_server_basic() {
    let chain_config = Arc::new(chain::config::create_testnet());
    let config = create_test_config();
    let host = config.host.clone();
    let soft_info = SoftwareInfo {
        user_agent: "foo1".try_into().unwrap(),
        version: SemVer::new(1, 2, 3),
    };

    let inner = InMemoryAuthority::empty(host.clone(), ZoneType::Primary, false);

    let auth = AuthorityImpl {
        config,
        chain_config,
        serial: Default::default(),
        inner,
        ipv4_addrs: Default::default(),
        ipv6_addrs: Default::default(),
    };

    let ip1: Ipv4Addr = "1.2.3.4".parse().unwrap();
    let ip2: Ipv6Addr = "2a00::1".parse().unwrap();
    handle_command(
        &auth,
        DnsServerCommand::AddAddress(ip1.into(), soft_info.clone()),
    );
    handle_command(&auth, DnsServerCommand::AddAddress(ip2.into(), soft_info));
    assert_eq!(auth.ipv4_addrs.lock().unwrap().len(), 1);
    assert_eq!(auth.ipv6_addrs.lock().unwrap().len(), 1);

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
    assert_eq!(auth.ipv4_addrs.lock().unwrap().len(), 0);
    assert_eq!(auth.ipv6_addrs.lock().unwrap().len(), 0);
}

mod same_software_version_addr_selection_test {
    use crate::dns_server::{MaxIpv4RecordsCount, MaxIpv6RecordsCount};

    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn test_impl(
        chain_config: Arc<ChainConfig>,
        addr_map: &BTreeMap<IpAddr, SoftwareInfo>,
        min_same_software_version_nodes_ratio: PerThousand,
        max_ipv4_records: MaxIpv4RecordsCount,
        max_ipv6_records: MaxIpv6RecordsCount,
        expected_same_soft_version_v4_addr_count: usize,
        expected_same_soft_version_v6_addr_count: usize,
        rng: &mut impl Rng,
    ) {
        let ipv4_addr_count = addr_map.keys().filter(|addr| addr.is_ipv4()).count();
        let ipv6_addr_count = addr_map.len() - ipv4_addr_count;
        let addrs = {
            let mut addrs = addr_map.keys().copied().collect::<Vec<_>>();
            addrs.shuffle(rng);
            addrs
        };

        let config = AuthorityImplConfig {
            host: "seed.mintlayer.org.".parse().unwrap(),
            // Prevent the creation of SOA and NS records, for simplicity.
            nameserver: None,
            mbox: None,
            min_same_software_version_nodes_ratio,
            max_ipv4_records: max_ipv4_records.clone(),
            max_ipv6_records: max_ipv6_records.clone(),
        };
        let cur_soft_info = SoftwareInfo::current(&chain_config);

        let inner = InMemoryAuthority::empty(config.host.clone(), ZoneType::Primary, false);
        let auth = AuthorityImpl {
            config,
            chain_config: Arc::clone(&chain_config),
            serial: Default::default(),
            inner,
            ipv4_addrs: Default::default(),
            ipv6_addrs: Default::default(),
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
        assert_eq!(
            selected_v4_addrs.len(),
            std::cmp::min(ipv4_addr_count, *max_ipv4_records)
        );
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
        assert_eq!(
            selected_v6_addrs.len(),
            std::cmp::min(ipv6_addr_count, *max_ipv6_records)
        );
        let same_soft_version_addr_count = selected_v6_addrs
            .iter()
            .filter(|addr| *addr_map.get(&(**addr).into()).unwrap() == cur_soft_info)
            .count();
        assert_eq!(
            same_soft_version_addr_count,
            expected_same_soft_version_v6_addr_count
        );
    }

    // The basic case - there are plenty of addresses, half of them have the current
    // software version. The selected addresses must have the correct proportion.
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn test_normal(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(chain::config::create_testnet());

        let max_ipv4_records_count: MaxIpv4RecordsCount = 40.into();
        let max_ipv6_records_count: MaxIpv6RecordsCount = 20.into();

        let v4_addr_count = 100;
        let v6_addr_count = 100;

        let v4_addrs = TestAddressMaker::new_distinct_random_ipv4_addrs(v4_addr_count, &mut rng);
        let v6_addrs = TestAddressMaker::new_distinct_random_ipv6_addrs(v6_addr_count, &mut rng);

        let addr_map = merge_btree_maps(
            make_software_infos(
                v4_addrs.into_iter().map(IpAddr::V4),
                &chain_config,
                v4_addr_count / 2,
                &mut rng,
            ),
            make_software_infos(
                v6_addrs.into_iter().map(IpAddr::V6),
                &chain_config,
                v6_addr_count / 2,
                &mut rng,
            ),
        );

        let same_software_nodes_ratio = PerThousand::new(800).unwrap();

        let expected_same_soft_version_v4_addr_count =
            (*max_ipv4_records_count as f64 * same_software_nodes_ratio.as_f64()) as usize;
        let expected_same_soft_version_v6_addr_count =
            (*max_ipv6_records_count as f64 * same_software_nodes_ratio.as_f64()) as usize;
        test_impl(
            chain_config,
            &addr_map,
            same_software_nodes_ratio,
            max_ipv4_records_count,
            max_ipv6_records_count,
            expected_same_soft_version_v4_addr_count,
            expected_same_soft_version_v6_addr_count,
            &mut rng,
        );
    }

    // Same as test_normal, but there are not enough addresses. All of them should be returned.
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn test_not_enough_addresses(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(chain::config::create_testnet());

        let max_ipv4_records_count: MaxIpv4RecordsCount = 400.into();
        let max_ipv6_records_count: MaxIpv6RecordsCount = 200.into();

        let v4_addr_count = 100;
        let v6_addr_count = 100;

        let v4_addrs = TestAddressMaker::new_distinct_random_ipv4_addrs(v4_addr_count, &mut rng);
        let v6_addrs = TestAddressMaker::new_distinct_random_ipv6_addrs(v6_addr_count, &mut rng);

        let addr_map = merge_btree_maps(
            make_software_infos(
                v4_addrs.into_iter().map(IpAddr::V4),
                &chain_config,
                v4_addr_count / 2,
                &mut rng,
            ),
            make_software_infos(
                v6_addrs.into_iter().map(IpAddr::V6),
                &chain_config,
                v6_addr_count / 2,
                &mut rng,
            ),
        );

        let same_software_nodes_ratio = PerThousand::new(800).unwrap();

        test_impl(
            chain_config,
            &addr_map,
            same_software_nodes_ratio,
            max_ipv4_records_count,
            max_ipv6_records_count,
            v4_addr_count / 2,
            v6_addr_count / 2,
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

        let max_ipv4_records_count: MaxIpv4RecordsCount = 40.into();
        let max_ipv6_records_count: MaxIpv6RecordsCount = 20.into();

        let v4_addr_count = 100;
        let v6_addr_count = 100;

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
            PerThousand::new(800).unwrap(),
            max_ipv4_records_count.clone(),
            max_ipv6_records_count.clone(),
            *max_ipv4_records_count,
            *max_ipv6_records_count,
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

        let max_ipv4_records_count: MaxIpv4RecordsCount = 40.into();
        let max_ipv6_records_count: MaxIpv6RecordsCount = 20.into();

        let v4_addr_count = 100;
        let v6_addr_count = 100;

        let v4_addrs = TestAddressMaker::new_distinct_random_ipv4_addrs(v4_addr_count, &mut rng);
        let v6_addrs = TestAddressMaker::new_distinct_random_ipv6_addrs(v6_addr_count, &mut rng);

        let addr_map = v4_addrs
            .into_iter()
            .map(IpAddr::V4)
            .chain(v6_addrs.into_iter().map(IpAddr::V6))
            .map(|addr| (addr, make_random_software_info(&mut rng)))
            .collect::<BTreeMap<_, _>>();

        test_impl(
            chain_config,
            &addr_map,
            PerThousand::new(800).unwrap(),
            max_ipv4_records_count,
            max_ipv6_records_count,
            0,
            0,
            &mut rng,
        );
    }

    // Check the case when the actual proportion of current-versioned vs other-versioned addresses
    // is bigger than the specified 'min_same_software_version_nodes_per_thousand'.
    // The actual proportion should be preferred.
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn test_higher_actual_proportion(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(chain::config::create_testnet());

        let max_ipv4_records_count: MaxIpv4RecordsCount = 40.into();
        let max_ipv6_records_count: MaxIpv6RecordsCount = 20.into();

        let v4_addr_count = 100;
        let v6_addr_count = 100;

        let v4_addrs = TestAddressMaker::new_distinct_random_ipv4_addrs(v4_addr_count, &mut rng);
        let v6_addrs = TestAddressMaker::new_distinct_random_ipv6_addrs(v6_addr_count, &mut rng);

        let min_same_software_nodes_ratio = PerThousand::new(800).unwrap();

        // 90 out of 100 addresses have the current software version, which is more than
        // min_same_software_nodes_ratio specified above.
        let addr_map = merge_btree_maps(
            make_software_infos(
                v4_addrs.into_iter().map(IpAddr::V4),
                &chain_config,
                90,
                &mut rng,
            ),
            make_software_infos(
                v6_addrs.into_iter().map(IpAddr::V6),
                &chain_config,
                90,
                &mut rng,
            ),
        );
        // The expected counts reflect the actual proportion of the current addresses, because it's
        // bigger.
        let expected_same_soft_version_v4_addr_count = 36;
        let expected_same_soft_version_v6_addr_count = 18;

        test_impl(
            chain_config.clone(),
            &addr_map,
            min_same_software_nodes_ratio,
            max_ipv4_records_count,
            max_ipv6_records_count,
            expected_same_soft_version_v4_addr_count,
            expected_same_soft_version_v6_addr_count,
            &mut rng,
        );
    }

    // Ask for 1 address exactly. Make sure that the effective same_software_nodes_ratio is bigger
    // than 0.5. 1 same-versioned address should be returned.
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn test_rounding_up(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(chain::config::create_testnet());

        let v4_addr_count = 100;
        let v6_addr_count = 100;

        let v4_addrs = TestAddressMaker::new_distinct_random_ipv4_addrs(v4_addr_count, &mut rng);
        let v6_addrs = TestAddressMaker::new_distinct_random_ipv6_addrs(v6_addr_count, &mut rng);

        // Note: both the actual and the requested proportions of same-version addresses are 0.6.
        let addr_map = merge_btree_maps(
            make_software_infos(
                v4_addrs.into_iter().map(IpAddr::V4),
                &chain_config,
                60,
                &mut rng,
            ),
            make_software_infos(
                v6_addrs.into_iter().map(IpAddr::V6),
                &chain_config,
                60,
                &mut rng,
            ),
        );

        test_impl(
            chain_config.clone(),
            &addr_map,
            PerThousand::new(600).unwrap(),
            1.into(),
            1.into(),
            1,
            1,
            &mut rng,
        );
    }

    // Ask for 1 address exactly. Make sure that the effective same_software_nodes_ratio is less
    // than 0.5. 0 same-versioned addresses should be returned.
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn test_rounding_down(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(chain::config::create_testnet());

        let v4_addr_count = 100;
        let v6_addr_count = 100;

        let v4_addrs = TestAddressMaker::new_distinct_random_ipv4_addrs(v4_addr_count, &mut rng);
        let v6_addrs = TestAddressMaker::new_distinct_random_ipv6_addrs(v6_addr_count, &mut rng);

        // Note: both the actual and the requested proportions of same-version addresses are 0.4.
        let addr_map = merge_btree_maps(
            make_software_infos(
                v4_addrs.into_iter().map(IpAddr::V4),
                &chain_config,
                40,
                &mut rng,
            ),
            make_software_infos(
                v6_addrs.into_iter().map(IpAddr::V6),
                &chain_config,
                40,
                &mut rng,
            ),
        );

        test_impl(
            chain_config,
            &addr_map,
            PerThousand::new(400).unwrap(),
            1.into(),
            1.into(),
            0,
            0,
            &mut rng,
        );
    }

    fn make_random_software_info(rng: &mut impl Rng) -> SoftwareInfo {
        SoftwareInfo {
            user_agent: "bogus".try_into().unwrap(),
            version: SemVer::new(rng.gen(), rng.gen(), rng.gen()),
        }
    }

    fn make_software_infos<Addr: Clone + Ord>(
        addrs: impl Iterator<Item = Addr>,
        chain_config: &ChainConfig,
        num_current_infos: usize,
        rng: &mut impl Rng,
    ) -> BTreeMap<Addr, SoftwareInfo> {
        addrs
            .enumerate()
            .map(move |(idx, addr)| {
                let soft_info = if idx < num_current_infos {
                    SoftwareInfo::current(chain_config)
                } else {
                    make_random_software_info(rng)
                };

                (addr.clone(), soft_info)
            })
            .collect::<BTreeMap<_, _>>()
    }
}
