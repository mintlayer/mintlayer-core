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

use rstest::rstest;
use test_utils::random::{make_seedable_rng, Rng, Seed};

use super::*;

fn assert_minimal<K: Ord, V: Eq + std::fmt::Debug>(map: &DefaultMap<K, V>) {
    for item in map.map.values() {
        assert_ne!(item, &map.default);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn from_iter(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let n_vals = rng.gen_range(1..1000);
    let init: Vec<(u8, u8)> = (0..n_vals).map(|_| (rng.gen(), rng.gen())).collect();

    let map: DefaultMap<u8, u8> = init.iter().cloned().collect();
    let map_dump: Vec<_> = (0..=u8::MAX).map(|i| *map.get(&i)).collect();
    assert_minimal(&map);

    let model = {
        let mut model = [0; 256];
        for (k, v) in init {
            model[k as usize] = v;
        }
        model
    };

    assert_eq!(map_dump, model);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn set_get(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut map = DefaultMap::<u8, u8>::with_custom_default(rng.gen());

    for _ in 0..100 {
        let key = rng.gen();
        let val = rng.gen();
        map.set(key, val);
        assert_eq!(val, *map.get(&key));
        assert_minimal(&map);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn operations(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let default_val: u8 = rng.gen();

    let mut map = DefaultMap::<u8, u8>::with_custom_default(default_val);
    let mut model = [default_val; 256];

    for _ in 0..1000 {
        match rng.gen_range(0..=6) {
            0..=3 => {
                let key = rng.gen();
                let val = rng.gen();
                let prev_model = model[key as usize];
                model[key as usize] = val;
                let prev_map = map.set(key, val);
                assert_eq!(*prev_map, prev_model);
            }
            4..=4 => {
                let key = rng.gen();
                let prev_model = model[key as usize];
                let prev_map = map.reset(&key);
                model[key as usize] = default_val;
                assert_eq!(*prev_map, prev_model);
            }
            5..=6 => {
                let key = rng.gen();
                let prev_model = model[key as usize];
                let mut value = map.get_mut(key);
                let prev_map = *value;
                *value = !*value;
                model[key as usize] = !model[key as usize];
                assert_eq!(prev_map, prev_model);
            }
            _ => panic!("Out of range"),
        }

        assert_minimal(&map);
        let map_dump: Vec<_> = (0..=u8::MAX).map(|i| *map.get(&i)).collect();
        assert_eq!(&model[..], &map_dump);
    }
}
