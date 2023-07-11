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

use super::test_helper::{create_tx_outputs, empty_test_utxos_view, UnwrapInfallible};
use crate::{
    ConsumedUtxoCache, FlushableUtxoView, UtxoSource, UtxosCache, UtxosTxUndoWithSources, UtxosView,
};
use common::{
    chain::{block::BlockReward, OutPointSourceId, Transaction, TxInput, UtxoOutPoint},
    primitives::{BlockHeight, Id, Idable, H256},
};
use crypto::random::{CryptoRng, Rng};
use rstest::rstest;
use std::{collections::BTreeMap, convert::Infallible};
use test_utils::random::{make_seedable_rng, Seed};

// Structure to store outpoints of current utxo set and info for undo
#[derive(Default)]
struct ResultWithUndo {
    utxo_outpoints: Vec<UtxoOutPoint>,
    outpoints_with_undo: BTreeMap<UtxoOutPoint, UndoInfo>,
}

struct UndoInfo {
    prev_outpoint: UtxoOutPoint,
    tx_undo: UtxosTxUndoWithSources,
}

// This test creates an arbitrary long chain of caches.
// Every new cache is populated with random block reward, spending transactions and undo of utxo.
// When the last cache in the chain is created and modified the chain starts to fold by flushing
// result to a parent. One by one the chain is folded back to a single cache that is checked for consistency.
#[rstest]
#[trace]
#[case(Seed::from_entropy(), 8, 1000)]
fn cache_simulation_with_undo(
    #[case] seed: Seed,
    #[case] nested_level: usize,
    #[case] iterations_per_cache: usize,
) {
    let mut rng = make_seedable_rng(seed);
    let mut result: ResultWithUndo = Default::default();
    let test_view = empty_test_utxos_view(H256::zero().into());
    let mut base = UtxosCache::new(test_view).unwrap_infallible();

    let new_consumed_cache =
        simulation_step(&mut rng, &mut result, &base, iterations_per_cache, nested_level);
    let new_consumed_cache = new_consumed_cache.unwrap();
    base.batch_write(new_consumed_cache).expect("batch write must succeed");

    for outpoint in &result.utxo_outpoints {
        let has_utxo = base.has_utxo(outpoint).unwrap_infallible();
        let utxo = base.utxo(outpoint).unwrap_infallible();
        assert_eq!(has_utxo, utxo.is_some());
        if utxo.is_some() {
            assert!(base.has_utxo_in_cache(outpoint));
        }
    }
}

/// A recursive function that hierarchically fills a cache, consumes it and returns it, recursively
/// In every call:
/// 1. Create a "current cache" from the given parent (current as in "this level")
/// 2. Populate the cache with with arbitrary outputs (in populate_...())
/// 3. Add all these new outputs to a global list of all outputs (all_outputs)
/// 4. Create a child from current cache by calling this function again (recursion)
/// 5. Flush the child into current cache
/// 6. Consume the current cache, and return it
fn simulation_step<P: UtxosView<Error = Infallible>>(
    rng: &mut (impl Rng + CryptoRng),
    all_outputs: &mut ResultWithUndo,
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
        populate_cache_with_undo(rng, &mut current_cache, iterations_per_cache, all_outputs);
    all_outputs.utxo_outpoints.append(&mut current_cache_outputs.utxo_outpoints);
    all_outputs
        .outpoints_with_undo
        .append(&mut current_cache_outputs.outpoints_with_undo);

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

fn populate_cache_with_undo<P: UtxosView<Error = Infallible>>(
    rng: &mut (impl Rng + CryptoRng),
    cache: &mut UtxosCache<P>,
    iterations_count: usize,
    prev_result: &mut ResultWithUndo,
) -> ResultWithUndo {
    // track outpoints of the current utxo set and info for undo
    let mut result: ResultWithUndo = Default::default();

    for _ in 0..iterations_count {
        let i = rng.gen_range(0..usize::MAX);
        // create new utxo
        if i % 20 < 19 {
            //create utxo from block reward
            if i % 20 < 10 {
                let reward = BlockReward::new(create_tx_outputs(rng, 1));
                let block_height = BlockHeight::new(rng.gen_range(0..iterations_count as u64));
                let block_id = Id::new(H256::random_using(rng));
                cache
                    .add_utxos_from_block_reward(
                        &reward,
                        UtxoSource::Blockchain(block_height),
                        &block_id,
                        false,
                    )
                    .unwrap();
                result
                    .utxo_outpoints
                    .push(UtxoOutPoint::new(OutPointSourceId::from(block_id), 0));
            } else {
                //spend random utxo in a transaction

                //get random outpoint from existing outpoints
                let outpoint = if rng.gen::<bool>() && !prev_result.utxo_outpoints.is_empty() {
                    let outpoint_idx = rng.gen_range(0..prev_result.utxo_outpoints.len());
                    //this outpoint will be spent so remove strait away
                    prev_result.utxo_outpoints.remove(outpoint_idx)
                } else if !result.utxo_outpoints.is_empty() {
                    let outpoint_idx = rng.gen_range(0..result.utxo_outpoints.len());
                    //this outpoint will be spent so remove strait away
                    result.utxo_outpoints.remove(outpoint_idx)
                } else {
                    continue; //no outputs to spend yet
                };

                //use this outpoint as input for transaction
                let input = TxInput::from_utxo(outpoint.tx_id(), outpoint.output_index());
                let tx = Transaction::new(0x00, vec![input], create_tx_outputs(rng, 1)).unwrap();

                //spent the transaction
                let block_height = BlockHeight::new(rng.gen_range(0..iterations_count as u64));
                let undo = cache.connect_transaction(&tx, block_height).unwrap();

                //keep result updated
                let new_outpoint = UtxoOutPoint::new(OutPointSourceId::from(tx.get_id()), 0);
                result.utxo_outpoints.push(new_outpoint.clone());
                result
                    .outpoints_with_undo
                    .insert(new_outpoint, UndoInfo { prev_outpoint: outpoint, tx_undo: undo });
            }
        } else if !result.outpoints_with_undo.is_empty() {
            //undo random transaction spending from current utxo set

            let idx = rng.gen_range(0..result.utxo_outpoints.len());
            let outpoint = result.utxo_outpoints.remove(idx);

            //spend new utxo
            cache.spend_utxo(&outpoint).unwrap();
            //restore previous utxo. Only outputs of a tx can be undone
            if let Some(undo_info) = result.outpoints_with_undo.remove(&outpoint) {
                cache
                    .add_utxo(
                        &undo_info.prev_outpoint,
                        undo_info.tx_undo.utxos()[0].clone().unwrap(),
                        cache.has_utxo(&undo_info.prev_outpoint).unwrap_infallible(),
                    )
                    .unwrap();

                //keep result updated
                result.utxo_outpoints.push(undo_info.prev_outpoint.clone());
            }
        }

        // every 100 iterations check full cache
        if i % 100 == 0 {
            for outpoint in &result.utxo_outpoints {
                let has_utxo = cache.has_utxo(outpoint).unwrap_infallible();
                let utxo = cache.utxo(outpoint).unwrap_infallible();
                assert_eq!(has_utxo, utxo.is_some());
            }
        }
    }

    result
}
