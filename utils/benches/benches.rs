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

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use randomness::make_pseudo_rng;
use utils::bloom_filters::rolling_bloom_filter::RollingBloomFilter;

pub fn rolling_bloom_bench(c: &mut Criterion) {
    let mut data = [0u8; 32];
    let mut rng = make_pseudo_rng();

    let mut list = RollingBloomFilter::<[u8; 32]>::new(120000, 0.000001, &mut rng);
    let mut count = 0u32;

    c.bench_function("RollingBloomFilter", |b| {
        b.iter(|| {
            count += 1;

            data[0..4].copy_from_slice(&count.to_le_bytes());
            list.insert(&data, &mut rng);

            data[0..4].copy_from_slice(&count.to_be_bytes());
            black_box(list.contains(&data));
        })
    });

    c.bench_function("RollingBloomFilter (insert only)", |b| {
        b.iter(|| {
            count += 1;

            data[0..4].copy_from_slice(&count.to_le_bytes());
            list.insert(&black_box(data), &mut rng);
        })
    });
}

criterion_group!(benches, rolling_bloom_bench);
criterion_main!(benches);
