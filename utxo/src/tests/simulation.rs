// // Copyright (c) 2022 RBB S.r.l
// // opensource@mintlayer.org
// // SPDX-License-Identifier: MIT
// // Licensed under the MIT License;
// // you may not use this file except in compliance with the License.
// // You may obtain a copy of the License at
// //
// // https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
// //
// // Unless required by applicable law or agreed to in writing, software
// // distributed under the License is distributed on an "AS IS" BASIS,
// // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// // See the License for the specific language governing permissions and
// // limitations under the License.

// use super::{test_helper::create_utxo, test_view};
// use crate::{FlushableUtxoView, UtxosCache, UtxosView};
// use common::{chain::OutPoint, primitives::H256};
// use crypto::random::Rng;
// use rstest::rstest;
// use test_utils::random::{make_seedable_rng, Seed};

// // This test creates an arbitrary long chain of caches.
// // Every new cache is populated with random utxo values which can be created/spend/removed.
// // When the last cache in the chain is created and modified the chain starts to fold by flushing
// // result to a parent. One by one the chain is folded back to a single cache that is checked for consistency.
// #[rstest]
// #[trace]
// #[case(Seed::from_entropy(), 10, 2000)]
// fn cache_simulation_test(
//     #[case] seed: Seed,
//     #[case] nested_level: usize,
//     #[case] iterations_per_cache: usize,
// ) {
//     let mut rng = make_seedable_rng(seed);
//     let mut result: Vec<OutPoint> = Vec::new();
//     let test_view = test_view();
//     let mut base = UtxosCache::new_for_test(H256::random().into(), &*test_view);

//     let new_cache = simulation_step(
//         &mut rng,
//         &mut result,
//         &base,
//         iterations_per_cache,
//         nested_level,
//     );
//     let consumed_cache = new_cache.unwrap().consume();
//     base.batch_write(consumed_cache).expect("batch write must succeed");

//     for outpoint in &result {
//         let has_utxo = base.has_utxo(outpoint);
//         let utxo = base.utxo(outpoint);
//         assert_eq!(has_utxo, utxo.is_some());
//         if utxo.is_some() {
//             assert!(base.has_utxo_in_cache(outpoint));
//         }
//     }
// }

// // Each step a new cache is created based on parent. Then it is randomly modified and passed to the
// // next step as a parent. After recursion stops the resulting cache is returned and flushed to the base.
// fn simulation_step<'a>(
//     rng: &mut impl Rng,
//     result: &mut Vec<OutPoint>,
//     parent: &'a UtxosCache,
//     iterations_per_cache: usize,
//     nested_level: usize,
// ) -> Option<UtxosCache<'a>> {
//     if nested_level == 0 {
//         return None;
//     }

//     let mut cache = UtxosCache::new(parent);
//     let mut new_cache_res = populate_cache(rng, &mut cache, iterations_per_cache, result);
//     result.append(&mut new_cache_res);

//     let new_cache = simulation_step(rng, result, &cache, iterations_per_cache, nested_level - 1);

//     if let Some(new_cache) = new_cache {
//         let consumed_cache = new_cache.consume();
//         cache.batch_write(consumed_cache).expect("batch write must succeed");
//     }

//     Some(cache)
// }

// // Perform random modification on a cache (add new, spend existing, uncache), tracking the coverage
// fn populate_cache(
//     rng: &mut impl Rng,
//     cache: &mut UtxosCache,
//     iterations_count: usize,
//     prev_result: &[OutPoint],
// ) -> Vec<OutPoint> {
//     let mut spent_an_entry = false;
//     let mut added_an_entry = false;
//     let mut removed_an_entry = false;
//     let mut verified_full_cache = false;
//     let mut missed_an_entry = false;
//     let mut found_an_entry = false;
//     // track outpoints
//     let mut result: Vec<OutPoint> = Vec::new();

//     for i in 0..iterations_count {
//         //select outpoint and utxo from existing or create new
//         let flip = rng.gen_range(0..3);
//         let (outpoint, utxo) = if flip == 0 && prev_result.len() > 1 {
//             let outpoint_idx = rng.gen_range(0..prev_result.len());
//             (prev_result[outpoint_idx].clone(), None)
//         } else if flip == 1 && result.len() > 1 {
//             let outpoint_idx = rng.gen_range(0..result.len());
//             (result[outpoint_idx].clone(), None)
//         } else {
//             let block_height = rng.gen_range(0..iterations_count);
//             let (utxo, outpoint) = create_utxo(rng, block_height.try_into().unwrap());

//             result.push(outpoint.clone());
//             (outpoint, Some(utxo))
//         };

//         // spend utxo or add new random one
//         if cache.has_utxo(&outpoint) {
//             assert!(cache.spend_utxo(&outpoint).is_ok());
//             spent_an_entry = true;
//         } else if utxo.is_some() {
//             let possible_overwrite = rng.gen::<bool>();
//             assert!(cache.add_utxo(&outpoint, utxo.unwrap(), possible_overwrite).is_ok());
//             added_an_entry = true;
//         }

//         // every 10 iterations call uncache
//         if i % 10 == 0 {
//             if rng.gen::<bool>() && prev_result.len() > 1 {
//                 let idx = rng.gen_range(0..prev_result.len());
//                 let _ = cache.uncache(&prev_result[idx]);
//             } else if result.len() > 1 {
//                 let idx = rng.gen_range(0..result.len());
//                 let _ = cache.uncache(&result[idx]);
//             }
//             removed_an_entry = true;
//         }

//         // every 100 iterations check full cache
//         if i % 100 == 0 {
//             for outpoint in &result {
//                 let has_utxo = cache.has_utxo(outpoint);
//                 let utxo = cache.utxo(outpoint);
//                 assert_eq!(has_utxo, utxo.is_some());
//                 if utxo.is_some() {
//                     assert!(cache.has_utxo_in_cache(outpoint));
//                     found_an_entry = true;
//                 }
//                 missed_an_entry = true;
//             }
//             verified_full_cache = true;
//         }
//     }

//     //check coverage
//     assert!(spent_an_entry);
//     assert!(added_an_entry);
//     assert!(removed_an_entry);
//     assert!(verified_full_cache);
//     assert!(found_an_entry);
//     assert!(missed_an_entry);

//     result
// }
