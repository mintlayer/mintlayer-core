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
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use common::chain::config::create_unit_test_config;
use criterion::{criterion_group, criterion_main, Criterion};

use p2p::{
    net::AsBannableAddress,
    peer_manager::peerdb::PeerDb,
    testing_utils::{
        peerdb_inmemory_store, test_p2p_config, RandomAddressMaker, TestTcpAddressMaker,
    },
};

pub fn peer_db(c: &mut Criterion) {
    let db_store = peerdb_inmemory_store();
    let chain_config = create_unit_test_config();
    let p2p_config = Arc::new(test_p2p_config());
    let mut peerdb = PeerDb::<SocketAddr, IpAddr, _>::new(
        &chain_config,
        p2p_config,
        Default::default(),
        db_store,
    )
    .unwrap();

    for _ in 0..100000 {
        peerdb.peer_discovered(TestTcpAddressMaker::new());
    }

    for _ in 0..1000 {
        peerdb.ban(TestTcpAddressMaker::new().as_bannable());
    }

    let normal_outbound = (0..5).map(|_| TestTcpAddressMaker::new()).collect::<BTreeSet<_>>();

    c.bench_function("PeerDb", |b| {
        b.iter(|| peerdb.select_new_outbound_addresses(&normal_outbound))
    });
}

criterion_group!(benches, peer_db);
criterion_main!(benches);
