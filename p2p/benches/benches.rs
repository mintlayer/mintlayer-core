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

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use common::chain::config::create_unit_test_config;
use criterion::{criterion_group, criterion_main, Criterion};

use p2p::{
    peer_manager::{address_groups::AddressGroup, peerdb::PeerDb},
    testing_utils::{peerdb_inmemory_store, test_p2p_config, TestAddressMaker},
};
use randomness::make_pseudo_rng;

pub fn peer_db(c: &mut Criterion) {
    let mut rng = make_pseudo_rng();
    let db_store = peerdb_inmemory_store();
    let chain_config = create_unit_test_config();
    let p2p_config = Arc::new(test_p2p_config());
    let mut peerdb =
        PeerDb::<_>::new(&chain_config, p2p_config, Default::default(), db_store).unwrap();

    for _ in 0..100000 {
        peerdb.peer_discovered(TestAddressMaker::new_random_address(&mut rng));
    }

    for _ in 0..1000 {
        peerdb.ban(
            TestAddressMaker::new_random_address(&mut rng).as_bannable(),
            Duration::from_secs(60 * 60 * 24),
        );
    }

    let outbound_addr_groups = (0..5)
        .map(|_| {
            let addr = TestAddressMaker::new_random_address(&mut rng);
            AddressGroup::from_peer_address(&addr.as_peer_address())
        })
        .collect::<BTreeSet<_>>();

    c.bench_function("PeerDb", |b| {
        b.iter(|| {
            peerdb.select_non_reserved_outbound_addresses(&outbound_addr_groups, &|_| true, 11)
        })
    });
}

criterion_group!(benches, peer_db);
criterion_main!(benches);
