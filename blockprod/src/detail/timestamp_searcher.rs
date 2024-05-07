// Copyright (c) 2021-2024 RBB S.r.l
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
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

use rayon::prelude::*;

use chainstate::{
    chainstate_interface::ChainstateInterface, BlockIndex, ChainstateHandle, NonZeroPoolBalances,
};
use chainstate_types::pos_randomness::PoSRandomness;
use common::{
    chain::{
        block::timestamp::BlockTimestamp, config::EpochIndex, ChainConfig, PoSConsensusVersion,
    },
    primitives::{BlockHeight, Compact},
    Uint256,
};
use consensus::{
    calc_pos_hash_from_prv_key, calculate_target_required_from_block_index, check_pos_hash,
    compact_target_to_target, ConsensusCreationError, ConsensusPoSError,
    PoSTimestampSearchInputData,
};
use crypto::vrf::{VRFPrivateKey, VRFPublicKey};
use logging::log;
use randomness::{CryptoRng, Rng};
use serialization::{Decode, Encode};
use utils::{ensure, once_destructor::OnceDestructor};

use crate::{
    detail::utils::{
        get_best_block_index, get_block_id_from_height, get_existing_block_index,
        get_existing_gen_block_index, get_pool_balances_at_heights, get_sealed_epoch_randomness,
        make_ancestor_getter, pos_data_from_header, pos_status_from_height, timestamp_add_secs,
    },
    BlockProductionError,
};

#[derive(Clone, Encode, Decode)]
struct SearchDataForHeight {
    sealed_epoch_randomness: PoSRandomness,
    epoch_index: u64,
    target_required: Compact,
    min_timestamp: BlockTimestamp,
    max_timestamp: BlockTimestamp,
    pool_balances: NonZeroPoolBalances,
    consensus_version: PoSConsensusVersion,
}

#[derive(Clone, Encode, Decode)]
pub struct TimestampSearchData {
    start_height: BlockHeight,
    data: Vec<SearchDataForHeight>,
    check_all_timestamps_between_blocks: bool,
}

impl TimestampSearchData {
    pub fn new(
        chainstate: &dyn ChainstateInterface,
        chain_config: &ChainConfig,
        secret_input_data: &PoSTimestampSearchInputData,
        min_height: BlockHeight,
        max_height: Option<BlockHeight>,
        seconds_to_check_for_height: u64,
        check_all_timestamps_between_blocks: bool,
    ) -> Result<Self, BlockProductionError> {
        // Note: the passes min_height/max_height specify heights at which a new block could
        // be produced. On the other hand, heights that are passed to and returned from
        // `get_pool_balances_at_heights` are the height that the best block had when those
        // balances were calculated. In order to convert from the former to the latter,
        // we must subtract one, which is done below.

        let best_block_index = get_best_block_index(chainstate)?;

        let best_height_plus_one = best_block_index.block_height().next_height();
        let max_height = max_height.unwrap_or(best_height_plus_one);
        let max_height = std::cmp::min(max_height, best_height_plus_one);

        ensure!(
            min_height.into_int() > 0 && min_height <= max_height,
            BlockProductionError::WrongHeightRange(min_height, max_height)
        );

        let pool_balances = {
            let _on_scope_exit = log_scope_exec_time("Obtaining pool balances");

            get_pool_balances_at_heights(
                chainstate,
                min_height.prev_height().expect("The height is known to be non-zero"),
                max_height.prev_height().expect("The height is known to be non-zero"),
                secret_input_data.pool_id(),
            )?
        };

        let min_height = if let Some((first_height, _)) = pool_balances.first_key_value() {
            first_height.next_height()
        } else {
            return Ok(Self {
                start_height: min_height,
                data: Vec::new(),
                check_all_timestamps_between_blocks,
            });
        };

        let mut block_index_from_last_iter: Option<BlockIndex> = None;
        let mut search_data =
            Vec::with_capacity((max_height.into_int() - min_height.into_int() + 1) as usize);

        for cur_height in min_height.iter_up_to_including(max_height) {
            let sealed_epoch_randomness =
                get_sealed_epoch_randomness(chain_config, chainstate, cur_height)?;
            let epoch_index = chain_config.epoch_index_from_height(&cur_height);
            let cur_pool_balances = pool_balances
                .get(&cur_height.prev_height().expect("The height is known to be non-zero"))
                .cloned()
                .expect("Balances must be present");
            let pos_status = pos_status_from_height(chain_config, cur_height)?;

            let (target_required, prev_block_timestamp, seconds_to_check) =
                if cur_height == best_height_plus_one {
                    let target_required = calculate_target_required_from_block_index(
                        chain_config,
                        &pos_status,
                        &best_block_index,
                        make_ancestor_getter(chainstate),
                    )
                    .map_err(ConsensusCreationError::StakingError)?;

                    (
                        target_required,
                        best_block_index.block_timestamp(),
                        seconds_to_check_for_height,
                    )
                } else {
                    let block_id = get_block_id_from_height(chainstate, cur_height)?
                        .classify(chain_config)
                        .chain_block_id()
                        .expect("Genesis at non-zero height");

                    let block_index = get_existing_block_index(chainstate, &block_id)?;

                    let target_required =
                        pos_data_from_header(block_index.block_header().header())?.compact_target();

                    let prev_block_timestamp =
                        if let Some(prev_block_index) = block_index_from_last_iter {
                            prev_block_index.block_timestamp()
                        } else {
                            let prev_block_id = *block_index.prev_block_id();
                            let prev_block_index =
                                get_existing_gen_block_index(chainstate, &prev_block_id)?;

                            prev_block_index.block_timestamp()
                        };

                    let seconds_to_check =
                        if cur_height == max_height || !check_all_timestamps_between_blocks {
                            seconds_to_check_for_height
                        } else {
                            assert!(block_index.block_timestamp() > prev_block_timestamp);
                            block_index.block_timestamp().as_int_seconds()
                                - prev_block_timestamp.as_int_seconds()
                                - 1
                        };

                    block_index_from_last_iter = Some(block_index);

                    (target_required, prev_block_timestamp, seconds_to_check)
                };

            let min_timestamp = timestamp_add_secs(prev_block_timestamp, 1)?;
            let max_timestamp = timestamp_add_secs(min_timestamp, seconds_to_check)?;
            let consensus_version = pos_status.get_chain_config().consensus_version();

            let data_for_height = SearchDataForHeight {
                sealed_epoch_randomness,
                epoch_index,
                target_required,
                min_timestamp,
                max_timestamp,
                pool_balances: cur_pool_balances,
                consensus_version,
            };

            search_data.push(data_for_height);
        }

        Ok(Self {
            start_height: min_height,
            data: search_data,
            check_all_timestamps_between_blocks,
        })
    }
}

/// Collect search data that can be subsequently passed into find_timestamps_for_staking
/// to perform timestamps search.
///
/// For each block height in the specified range, the search will find timestamps where staking
/// is/was possible.
///
/// `min_height` must not be zero; `max_height` must not exceed the best block height plus one
/// (this value is assumed if `None` is passed).
///
/// If `check_all_timestamps_between_blocks` is false, `seconds_to_check_for_height + 1` is
/// the number of seconds that will be checked at each height in the range.
/// If `check_all_timestamps_between_blocks` is true, `seconds_to_check_for_height` only applies
/// to the last height in the range; for all other heights the maximum timestamp is the timestamp
/// of the next block.
pub async fn collect_timestamp_search_data(
    chainstate_handle: &ChainstateHandle,
    chain_config: Arc<ChainConfig>,
    secret_input_data: PoSTimestampSearchInputData,
    min_height: BlockHeight,
    max_height: Option<BlockHeight>,
    seconds_to_check_for_height: u64,
    check_all_timestamps_between_blocks: bool,
) -> Result<TimestampSearchData, BlockProductionError> {
    let search_data = chainstate_handle
        .call({
            move |chainstate| -> Result<_, BlockProductionError> {
                let _on_scope_exit = log_scope_exec_time("Creating search data");

                TimestampSearchData::new(
                    chainstate,
                    &chain_config,
                    &secret_input_data,
                    min_height,
                    max_height,
                    seconds_to_check_for_height,
                    check_all_timestamps_between_blocks,
                )
            }
        })
        .await??;

    Ok(search_data)
}

/// Complete the timestamp search.
///
/// Note: though the search is performed in parallel using `rayon`'s parallel iterators,
/// it may still require multiple seconds (or even minutes) to complete, depending on the
/// height range and the number of timestamps that must be checked. So it's not a good idea
/// to perform this call across an RPC boundary, because it will time out.
pub async fn find_timestamps_for_staking(
    chain_config: Arc<ChainConfig>,
    secret_input_data: PoSTimestampSearchInputData,
    search_data: TimestampSearchData,
) -> Result<BTreeMap<BlockHeight, Vec<BlockTimestamp>>, BlockProductionError> {
    let task_join_result = tokio::task::spawn_blocking({
        move || find_timestamps_for_staking_impl(&search_data, &chain_config, &secret_input_data)
    })
    .await;

    match task_join_result {
        Ok(result) => {
            let timestamps_map = result?;
            Ok(timestamps_map)
        }
        Err(join_err) => {
            if join_err.is_panic() {
                std::panic::resume_unwind(join_err.into_panic());
            }
            Err(BlockProductionError::Cancelled)
        }
    }
}

fn find_timestamps_for_staking_impl(
    search_data: &TimestampSearchData,
    chain_config: &ChainConfig,
    secret_input_data: &PoSTimestampSearchInputData,
) -> Result<BTreeMap<BlockHeight, Vec<BlockTimestamp>>, BlockProductionError> {
    let _on_scope_exit = log_scope_exec_time("Total timestamps searching");

    let timestamps_map = Mutex::new(BTreeMap::new());

    let vrf_pub_key = VRFPublicKey::from_private_key(secret_input_data.vrf_private_key());

    let precomputed_hashes = if search_data.check_all_timestamps_between_blocks {
        // In this case, timestamps will never overlap, so precomputing the hashes
        // will just add an overhead of extra allocations.
        None
    } else {
        // In this case, timestamps may overlap; if the overlap is significant,
        // the overhead of calculating the same hashes multiple times will outweigh
        // the one produced by allocations.

        let hash_inputs = {
            let _on_scope_exit = log_scope_exec_time("Collecting hash inputs");
            collect_distinct_hash_inputs(search_data)
        };

        let hashes_vec_list = {
            let _on_scope_exit = log_scope_exec_time("Calculating hashes");

            hash_inputs
                .par_iter()
                .map_init(
                    randomness::make_true_rng,
                    |rng, (timestamp, epoch_index, sealed_epoch_randomness)| {
                        calc_pos_hash_from_prv_key(
                            *epoch_index,
                            sealed_epoch_randomness,
                            *timestamp,
                            &vrf_pub_key,
                            secret_input_data.vrf_private_key(),
                            rng,
                        )
                        .map(|hash| ((*timestamp, *epoch_index, *sealed_epoch_randomness), hash))
                    },
                )
                .collect_vec_list()
        };

        let hashes = {
            let _on_scope_exit = log_scope_exec_time("Putting hashes in a map");

            itertools::process_results(
                hashes_vec_list.into_iter().flat_map(|vec| vec.into_iter()),
                |iter| iter.collect::<BTreeMap<_, _>>(),
            )
            .map_err(ConsensusCreationError::StakingError)?
        };

        Some(hashes)
    };

    {
        let _on_scope_exit = log_scope_exec_time("Actual timestamps searching");

        search_data
            .data
            .par_iter()
            .enumerate()
            .map_init(randomness::make_true_rng, |rng, (idx, item)| {
                let cur_height = search_data
                    .start_height
                    .checked_add(idx as u64)
                    .expect("The height is known to be below the maximum");

                let timestamps = find_timestamps(
                    chain_config,
                    item.consensus_version,
                    item.target_required,
                    item.min_timestamp,
                    item.max_timestamp,
                    &item.sealed_epoch_randomness,
                    item.epoch_index,
                    &item.pool_balances,
                    &vrf_pub_key,
                    secret_input_data.vrf_private_key(),
                    rng,
                    precomputed_hashes.as_ref(),
                )
                .map_err(ConsensusCreationError::StakingError)?;

                if !timestamps.is_empty() {
                    let mut timestamps_map = timestamps_map.lock().expect("poisoned mutex");
                    timestamps_map.insert(cur_height, timestamps);
                }

                Ok::<_, BlockProductionError>(())
            })
            .reduce(
                || Ok::<_, BlockProductionError>(()),
                |res1, res2| {
                    if res1.is_err() {
                        res1
                    } else {
                        res2
                    }
                },
            )?
    };

    Ok(timestamps_map.into_inner().expect("poisoned mutex"))
}

#[allow(clippy::too_many_arguments)]
fn find_timestamps(
    chain_config: &ChainConfig,
    consensus_version: PoSConsensusVersion,
    target: Compact,
    first_timestamp: BlockTimestamp,
    max_timestamp: BlockTimestamp,
    sealed_epoch_randomness: &PoSRandomness,
    epoch_index: EpochIndex,
    pool_balances: &NonZeroPoolBalances,
    vrf_pub_key: &VRFPublicKey,
    vrf_prv_key: &VRFPrivateKey,
    rng: &mut (impl Rng + CryptoRng),
    precomputed_hashes: Option<
        &BTreeMap<
            (
                BlockTimestamp,
                EpochIndex,
                /*sealed_epoch_randomness:*/ PoSRandomness,
            ),
            Uint256,
        >,
    >,
) -> Result<Vec<BlockTimestamp>, ConsensusPoSError> {
    let final_supply = chain_config
        .final_supply()
        .ok_or(ConsensusPoSError::FiniteTotalSupplyIsRequired)?;

    let target = compact_target_to_target(target)?;
    let final_supply = final_supply.to_amount_atoms();

    ensure!(
        first_timestamp <= max_timestamp,
        ConsensusPoSError::FutureTimestampInThePast
    );

    let mut timestamps = Vec::new();

    for cur_timestamp in first_timestamp.iter_up_to_including(max_timestamp) {
        let hash = if let Some(precomputed_hashes) = precomputed_hashes {
            *precomputed_hashes
                .get(&(cur_timestamp, epoch_index, *sealed_epoch_randomness))
                .expect("all hashes are pre-computed")
        } else {
            calc_pos_hash_from_prv_key(
                epoch_index,
                sealed_epoch_randomness,
                cur_timestamp,
                vrf_pub_key,
                vrf_prv_key,
                rng,
            )?
        };

        if check_pos_hash(
            consensus_version,
            &hash,
            &target,
            pool_balances.staker_balance(),
            pool_balances.total_balance(),
            final_supply,
        )
        .is_ok()
        {
            timestamps.push(cur_timestamp);
        }
    }

    Ok(timestamps)
}

fn collect_distinct_hash_inputs(
    search_data: &TimestampSearchData,
) -> BTreeSet<(BlockTimestamp, EpochIndex, PoSRandomness)> {
    let mut result = BTreeSet::new();

    for item in search_data.data.iter() {
        for timestamp in item.min_timestamp.iter_up_to_including(item.max_timestamp) {
            result.insert((timestamp, item.epoch_index, item.sealed_epoch_randomness));
        }
    }

    result
}

fn log_scope_exec_time(scope_name: &'_ str) -> OnceDestructor<impl FnOnce() + '_> {
    let start_time = std::time::Instant::now();

    OnceDestructor::new(move || {
        log::debug!("{scope_name} took {:?}", start_time.elapsed());
    })
}
