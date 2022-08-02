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

//TODO: need a better way than this.

use crate::{
    flush_to_base,
    utxo_impl::test_helper::{create_utxo, DIRTY, FRESH},
    UtxoEntry, UtxoStatus, UtxosCache, UtxosView,
};
use common::{
    chain::OutPoint,
    primitives::{Id, H256},
};
use crypto::random::Rng;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

fn populate_cache<'a>(
    rng: &mut impl Rng,
    parent: &'a UtxosCache,
    new_utxo_count: u64,
    existing_outpoints: &[OutPoint],
) -> (UtxosCache<'a>, Vec<OutPoint>) {
    let mut cache = UtxosCache::new(parent);
    // tracker
    let mut outpoints: Vec<OutPoint> = vec![];

    // let's add utxos based on `size`.
    for _ in 0..new_utxo_count {
        let block_height = rng.gen_range(0..new_utxo_count);
        let (utxo, outpoint) = create_utxo(rng, block_height);

        let outpoint = if rng.gen::<bool>() && existing_outpoints.len() > 1 {
            // setting a random existing 'spent' outpoint
            let outpoint_idx = rng.gen_range(0..existing_outpoints.len());
            existing_outpoints[outpoint_idx].clone()
        } else {
            // tracking the outpoints
            outpoints.push(outpoint.clone());
            outpoint
        };

        // randomly set the `possible_overwrite`
        let possible_overwrite = rng.gen::<bool>();
        let _ = cache.add_utxo(&outpoint, utxo, possible_overwrite);
    }

    // let's create half of the outpoints provided, to be marked as spent.
    // there's a possibility when randomly the same outpoint is used, so half seems okay.
    let spent_size = outpoints.len() / 2;

    for _ in 0..spent_size {
        // randomly select which outpoint should be marked as "spent"
        if rng.gen::<bool>() && existing_outpoints.len() > 1 {
            // just call the `spend_utxo`. Does not matter if it removes the outpoint entirely,
            // or just mark it as `spent`,
            let outp_idx = rng.gen_range(0..existing_outpoints.len());
            let to_spend = &existing_outpoints[outp_idx];
            let _ = cache.spend_utxo(to_spend);
        } else {
            // just mark it as "spent"
            let outp_idx = rng.gen_range(0..outpoints.len());
            let to_spend = &outpoints[outp_idx];

            // randomly select which flags should the spent utxo have.
            // 0 - NOT FRESH, NOT DIRTY, 1 - FRESH, 2 - DIRTY, 3 - FRESH AND DIRTY
            let flags = rng.gen_range(0..4u8);

            let new_entry = match flags {
                FRESH => UtxoEntry {
                    status: UtxoStatus::Spent,
                    is_dirty: false,
                    is_fresh: true,
                },
                DIRTY => UtxoEntry {
                    status: UtxoStatus::Spent,
                    is_dirty: true,
                    is_fresh: false,
                },
                flag if flag == (FRESH + DIRTY) => UtxoEntry {
                    status: UtxoStatus::Spent,
                    is_dirty: true,
                    is_fresh: true,
                },
                _ => UtxoEntry {
                    status: UtxoStatus::Spent,
                    is_dirty: false,
                    is_fresh: false,
                },
            };
            cache.utxos.insert(to_spend.clone(), new_entry);
        };
    }

    (cache, outpoints)
}

#[rstest]
#[case("8887871176094693639")]
#[trace]
#[case(Seed::from_entropy())]
fn stack_flush_test(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut outpoints: Vec<OutPoint> = vec![];

    let mut parent = UtxosCache::new_for_test(H256::random().into());

    let parent_clone = parent.clone();
    let new_utxo_count1 = rng.gen_range(0..50);
    let (cache1, mut cache1_outps) =
        populate_cache(&mut rng, &parent_clone, new_utxo_count1, &outpoints);
    outpoints.append(&mut cache1_outps);

    let cache1_clone = cache1.clone();
    let new_utxo_count2 = rng.gen_range(0..50);
    let (cache2, mut cache2_outps) =
        populate_cache(&mut rng, &cache1_clone, new_utxo_count2, &outpoints);
    outpoints.append(&mut cache2_outps);

    let cache2_clone = cache2.clone();
    let cache3_utxos_size = rng.gen_range(0..50);
    let (mut cache3, mut cache3_outps) =
        populate_cache(&mut rng, &cache2_clone, cache3_utxos_size, &outpoints);
    outpoints.append(&mut cache3_outps);

    let new_block_hash = Id::new(H256::random());
    cache3.set_best_block(new_block_hash);
    let cache3_clone = cache3.clone();
    assert!(flush_to_base(cache3_clone, &mut parent).is_ok());

    for (outpoint, utxo_entry) in &parent.utxos {
        let utxo = cache3.utxo(outpoint);
        assert_eq!(utxo_entry.utxo(), utxo);
    }
}
