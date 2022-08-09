// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{utxo_impl::test_helper::create_utxo, FlushableUtxoView, Utxo, UtxosCache, UtxosView};
use common::{chain::OutPoint, primitives::H256};
use crypto::random::Rng;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

const NUM_SIMULATION_ITERATIONS: usize = 40_000;

fn populate_cache(
    rng: &mut impl Rng,
    cache: &mut UtxosCache,
    iterations_count: u64,
    prev_result: &[(OutPoint, Utxo)],
) -> Vec<(OutPoint, Utxo)> {
    let mut spent_an_entry = false;
    let mut added_an_entry = false;
    let mut removed_an_entry = false;
    let mut verified_full_cache = false;
    let mut missed_an_entry = false;
    let mut found_an_entry = false;
    // track outpoints and utxos
    let mut result: Vec<(OutPoint, Utxo)> = Vec::new();

    for _ in 0..iterations_count {
        // select outpoint and utxo from existing or create new
        let flip = rng.gen_range(0..3);
        let (outpoint, utxo) = if flip == 0 && prev_result.len() > 1 {
            let outpoint_idx = rng.gen_range(0..prev_result.len());
            (prev_result[outpoint_idx].0.clone(), None)
        } else if flip == 1 && result.len() > 1 {
            let outpoint_idx = rng.gen_range(0..result.len());
            (result[outpoint_idx].0.clone(), None)
        } else {
            let block_height = rng.gen_range(0..iterations_count);
            let (utxo, outpoint) = create_utxo(rng, block_height);

            result.push((outpoint.clone(), utxo.clone()));
            (outpoint, Some(utxo))
        };

        // spend utxo or add new random one
        if cache.has_utxo(&outpoint) {
            assert!(cache.spend_utxo(&outpoint).is_ok());
            spent_an_entry = true;
        } else if utxo.is_some() {
            let possible_overwrite = rng.gen::<bool>();
            assert!(cache.add_utxo(&outpoint, utxo.unwrap(), possible_overwrite).is_ok());
            added_an_entry = true;
        }

        // every 10 iterations call uncache
        if rng.gen_range(0..10) == 0 {
            if rng.gen::<bool>() && prev_result.len() > 1 {
                let idx = rng.gen_range(0..prev_result.len());
                cache.uncache(&prev_result[idx].0);
            } else if result.len() > 1 {
                let idx = rng.gen_range(0..result.len());
                cache.uncache(&result[idx].0);
            }
            removed_an_entry = true;
        }

        // every 100 iterations check full cache
        if rng.gen_range(0..100) == 0 {
            for (outpoint, _) in &result {
                let has_utxo = cache.has_utxo(&outpoint);
                let utxo = cache.utxo(&outpoint);
                assert_eq!(has_utxo, utxo.is_some());
                if utxo.is_some() {
                    assert!(cache.has_utxo_in_cache(outpoint));
                    found_an_entry = true;
                }
                missed_an_entry = true;
            }
            verified_full_cache = true;
        }
    }

    //check coverage
    assert!(spent_an_entry);
    assert!(added_an_entry);
    assert!(removed_an_entry);
    assert!(verified_full_cache);
    assert!(found_an_entry);
    assert!(missed_an_entry);

    result
}

fn simulation_step<'a>(
    rng: &mut impl Rng,
    result: &mut Vec<(OutPoint, Utxo)>,
    parent: &'a UtxosCache,
    steps: usize,
) -> Option<UtxosCache<'a>> {
    if steps == 0 {
        return None;
    }
    let mut cache = UtxosCache::new(parent);

    let mut new_cache_res = populate_cache(rng, &mut cache, 2000, &result);
    result.append(&mut new_cache_res);

    let new_cache = simulation_step(rng, result, &cache, steps - 1);

    if let Some(new_cache) = new_cache {
        cache
            .batch_write(new_cache.clone().consume())
            .expect("batch write must succeed");
    }

    Some(cache)
}

// should ignore by default? because they take too long
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn cache_simulation_test(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut result: Vec<(OutPoint, Utxo)> = Vec::new();
    let mut base = UtxosCache::new_for_test(H256::random().into());

    let new_cache = simulation_step(&mut rng, &mut result, &base, 10);
    base.batch_write(new_cache.unwrap().consume())
        .expect("batch write must succeed");

    for (outpoint, _) in &result {
        let has_utxo = base.has_utxo(&outpoint);
        let utxo = base.utxo(&outpoint);
        assert_eq!(has_utxo, utxo.is_some());
        if utxo.is_some() {
            assert!(base.has_utxo_in_cache(outpoint));
        }
    }
}

//#[ignore]
//#[rstest]
//#[trace]
//#[case(Seed::from_entropy())]
//fn cache_simulation_test(#[case] seed: Seed) {
//    let mut rng = make_seedable_rng(seed);
//    let mut caches = vec![UtxosCache::new_for_test(H256::random().into())];
//
//    let mut expected_utxos: BTreeMap<OutPoint, Option<Utxo>> = BTreeMap::new();
//
//    let txids = {
//        let mut tmp: Vec<Id<Transaction>> = Vec::with_capacity(NUM_SIMULATION_ITERATIONS / 8);
//        for _ in 0..NUM_SIMULATION_ITERATIONS / 8 {
//            tmp.push(Id::new(H256::random()));
//        }
//        tmp
//    };
//
//    let outpoint_from_idx =
//        |idx: usize| OutPoint::new(OutPointSourceId::Transaction(txids[idx]), 0);
//
//    for _ in 0..NUM_SIMULATION_ITERATIONS {
//        let caches_len = caches.len();
//        let cache = &mut caches[caches_len];
//
//        let txid = outpoint_from_idx(rng.gen_range(0..txids.len()));
//        if cache.has_utxo(&txid) {
//        } else {
//            let block_height = rng.gen_range(0..NUM_SIMULATION_ITERATIONS);
//            //let (utxo, outpoint) = create_utxo(&mut rng, block_height);
//        }
//    }
//}
