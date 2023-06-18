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

use chainstate_test_framework::TestFramework;
use common::primitives::Idable;
use test_utils::random::make_seedable_rng;

use criterion::{criterion_group, criterion_main, Criterion};

// TODO: rework for PoS
pub fn reorg(c: &mut Criterion) {
    let mut rng = make_seedable_rng(1111.into());
    let mut tf = TestFramework::builder(&mut rng).build();

    let common_block_id = tf.create_chain(&tf.genesis().get_id().into(), 5, &mut rng).unwrap();

    tf.create_chain(&common_block_id, 1000, &mut rng).unwrap();

    c.bench_function("Reorg", |b| {
        b.iter(|| tf.create_chain(&common_block_id, 1001, &mut rng).unwrap())
    });
}

criterion_group!(benches, reorg);
criterion_main!(benches);
