// Copyright (c) 2022 RBB S.r.l
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

use std::convert::Infallible;

use super::test_helper::{create_utxo, empty_test_utxos_view, UnwrapInfallible};
use crate::{ConsumedUtxoCache, FlushableUtxoView, UtxosCache, UtxosView};
use common::chain::UtxoOutPoint;
use crypto::random::{CryptoRng, Rng};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

// This test creates an arbitrary long chain of caches.
// Every new cache is populated with random utxo values which can be created/spend/removed.
// When the last cache in the chain is created and modified the chain starts to fold by flushing
// result to a parent. One by one the chain is folded back to a single cache that is checked for consistency.
#[rstest]
#[trace]
#[case(Seed::from_entropy(), 10, 2000)]
fn cache_simulation_test(
    #[case] seed: Seed,
    #[case] nested_level: usize,
    #[case] iterations_per_cache: usize,
) {
    let mut rng = make_seedable_rng(seed);
    let mut result: Vec<UtxoOutPoint> = Vec::new();
    let test_view = empty_test_utxos_view(common::primitives::H256::zero().into());
    let mut base = UtxosCache::new(test_view).unwrap_infallible();

    let new_consumed_cache =
        simulation_step(&mut rng, &mut result, &base, iterations_per_cache, nested_level);
    let new_consumed_cache = new_consumed_cache.unwrap();
    base.batch_write(new_consumed_cache).expect("batch write must succeed");

    for outpoint in &result {
        let has_utxo = base.has_utxo(outpoint).unwrap_infallible();
        let utxo = base.utxo(outpoint).unwrap_infallible();
        assert_eq!(has_utxo, utxo.is_some());
        if utxo.is_some() {
            assert!(base.has_utxo_in_cache(outpoint));
        }
    }
}

/// Recursive function that hierarchically filles a cache, consumes it and returns it, recursively
/// In every call:
/// 1. Create a "current cache" from the given parent (current as in "this level")
/// 2. Populate the cache with with arbitrary outputs (in populate_...())
/// 3. Add all these new outputs to a global list of all outputs (all_outputs)
/// 4. Create a child from current cache by calling this function again (recursion)
/// 5. Flush the child into current cache
/// 6. Consume the current cache, and return it
fn simulation_step<P: UtxosView<Error = Infallible>>(
    rng: &mut (impl Rng + CryptoRng),
    all_outputs: &mut Vec<UtxoOutPoint>,
    parent_cache: &UtxosCache<P>,
    iterations_per_cache: usize,
    nested_level: usize,
) -> Option<ConsumedUtxoCache> {
    if nested_level == 0 {
        return None;
    }

    // notice that we're using a reference of a reference
    let parent: &dyn UtxosView<Error = Infallible> = parent_cache;
    let mut current_cache = UtxosCache::new(&parent).unwrap_infallible();

    // fill a global list of outputs
    let mut current_cache_outputs =
        populate_cache(rng, &mut current_cache, iterations_per_cache, all_outputs);
    all_outputs.append(&mut current_cache_outputs);

    // create the child
    let child_cache_op =
        simulation_step(rng, all_outputs, &current_cache, iterations_per_cache, nested_level - 1);

    // flush child into current cache
    if let Some(child_cache) = child_cache_op {
        current_cache.batch_write(child_cache).expect("batch write must succeed");
    }

    // return the consumed cache
    let consumed_cache = current_cache.consume();
    Some(consumed_cache)
}

// Perform random modification on a cache (add new, spend existing, uncache), tracking the coverage
fn populate_cache<P: UtxosView<Error = Infallible>>(
    rng: &mut (impl Rng + CryptoRng),
    cache: &mut UtxosCache<P>,
    iterations_count: usize,
    prev_result: &[UtxoOutPoint],
) -> Vec<UtxoOutPoint> {
    let mut spent_an_entry = false;
    let mut added_an_entry = false;
    let mut removed_an_entry = false;
    let mut verified_full_cache = false;
    let mut missed_an_entry = false;
    let mut found_an_entry = false;
    // track outpoints
    let mut result: Vec<UtxoOutPoint> = Vec::new();

    for i in 0..iterations_count {
        //select outpoint and utxo from existing or create new
        let flip = rng.gen_range(0..3);
        let (outpoint, utxo) = if flip == 0 && prev_result.len() > 1 {
            let outpoint_idx = rng.gen_range(0..prev_result.len());
            (prev_result[outpoint_idx].clone(), None)
        } else if flip == 1 && result.len() > 1 {
            let outpoint_idx = rng.gen_range(0..result.len());
            (result[outpoint_idx].clone(), None)
        } else {
            let block_height = rng.gen_range(0..iterations_count);
            let (utxo, outpoint) = create_utxo(rng, block_height.try_into().unwrap());

            result.push(outpoint.clone());
            (outpoint, Some(utxo))
        };

        // spend utxo or add new random one
        if cache.has_utxo(&outpoint).unwrap_infallible() {
            assert!(cache.spend_utxo(&outpoint).is_ok());
            spent_an_entry = true;
        } else if utxo.is_some() {
            let possible_overwrite = rng.gen::<bool>();
            assert!(cache.add_utxo(&outpoint, utxo.unwrap(), possible_overwrite).is_ok());
            added_an_entry = true;
        }

        // every 10 iterations call uncache
        if i % 10 == 0 {
            if rng.gen::<bool>() && prev_result.len() > 1 {
                let idx = rng.gen_range(0..prev_result.len());
                let _ = cache.uncache(&prev_result[idx]);
            } else if result.len() > 1 {
                let idx = rng.gen_range(0..result.len());
                let _ = cache.uncache(&result[idx]);
            }
            removed_an_entry = true;
        }

        // every 100 iterations check full cache
        if i % 100 == 0 {
            for outpoint in &result {
                let has_utxo = cache.has_utxo(outpoint).unwrap_infallible();
                let utxo = cache.utxo(outpoint).unwrap_infallible();
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
