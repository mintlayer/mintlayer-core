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
    sync::Arc,
};

use chainstate_types::pos_randomness::PoSRandomness;
use crypto::{
    key::PrivateKey,
    vrf::{VRFPrivateKey, VRFReturn},
};
use serialization::Encode;
use tokio::sync::{oneshot, watch};

use ::utils::{atomics::RelaxedAtomicBool, once_destructor::OnceDestructor};
use chainstate::{chainstate_interface::ChainstateInterface, GenBlockIndex};
use common::{
    chain::{
        block::{
            block_body::BlockBody,
            consensus_data::PoSData,
            signed_block_header::{
                BlockHeaderSignature, BlockHeaderSignatureData, SignedBlockHeader,
            },
            timestamp::BlockTimestamp,
            BlockHeader, BlockReward, ConsensusData,
        },
        config::EpochIndex,
        Block, ChainConfig, GenBlock, PoSChainConfig, PoWStatus, PoolId, RequiredConsensus,
    },
    primitives::{BlockHeight, Compact, Id},
    Uint256,
};
use consensus::{
    calculate_target_required_from_block_index, compact_target_to_target,
    generate_pos_consensus_data_and_reward, generate_pow_consensus_data_and_reward,
    generate_reward_ignore_consensus, mine, stake, ConsensusCreationError, ConsensusPoSError,
    ConsensusPoWError, GenerateBlockInputData, MiningResult, PoSGenerateBlockInputData,
    PoSPartialConsensusData, PoSSlotInfo, PoSSlotInfoCmpByParentTS, PoWGenerateBlockInputData,
    StakeResult,
};

use crate::BlockProductionError;

use super::{
    utils::{
        get_existing_gen_block_index, get_pool_balances_at_heights, get_sealed_epoch_randomness,
        make_ancestor_getter, timestamp_add_secs,
    },
    BlockProduction, TxData,
};

impl BlockProduction {
    async fn pull_block_solver_input_data_pos(
        &self,
        input_data: PoSGenerateBlockInputData,
        best_block_index: GenBlockIndex,
        transactions: TxData,
    ) -> Result<(PoSBlockSolverInputData, watch::Receiver<BlockTimestamp>), BlockProductionError>
    {
        let last_used_block_timestamp_for_pos =
            self.get_last_used_block_timestamp_for_pos_data(&input_data);

        let min_timestamp = {
            // If last_used_block_timestamp_for_pos is None, the pool has just been created or the node has been restarted.
            // In such a case, we just start from the tip.
            // Note that though it might be tempting to start from some block in the recent past (where a reorg to the new block
            // would still be probable, e.g. 1h in the past), it might not be a good idea because:
            // 1) Though the later call to collect_pos_slot_infos validates the min timestamp, ensuring that we don't go below the
            // point where we've already produced a block using this pool, it does so only for mainchain blocks.
            // If we start from a block in the past here, we'll have to check stale chains too (so that we don't stake twice
            // for the same timestamp); this won't work if the node has been restarted after deleting the chainstate db.
            // 2) It doesn't look like we'd gain much by doing so.
            let prev_timestamp =
                last_used_block_timestamp_for_pos.unwrap_or(best_block_index.block_timestamp());

            timestamp_add_secs(prev_timestamp, 1)?
        };
        let max_timestamp = BlockTimestamp::from_time(self.time_getter.get_time());

        if min_timestamp > max_timestamp {
            return Err(BlockProductionError::TryAgainLater);
        }

        let (last_used_block_timestamp_sender, last_used_block_timestamp_receiver) =
            watch::channel(min_timestamp);

        let cur_tip_chain_trust = best_block_index.chain_trust();
        let stake_private_key = input_data.stake_private_key().clone();
        let vrf_private_key = input_data.vrf_private_key().clone();
        let (consensus_data, block_reward) =
            generate_pos_consensus_data_and_reward(input_data, randomness::make_true_rng())?;

        let pool_id = consensus_data.pool_id;

        let slot_infos = self
            .chainstate_handle
            .call(move |cs| -> Result<_, BlockProductionError> {
                collect_pos_slot_infos(cs, &pool_id, min_timestamp, best_block_index)
            })
            .await??;

        let first_slot_info = slot_infos.first().expect("parents map must be non-empty");
        let earliest_parent_timestamp = first_slot_info.0.slot_info.parent_timestamp;
        let min_possible_timestamp = timestamp_add_secs(earliest_parent_timestamp, 1)?;
        let min_timestamp = std::cmp::max(min_timestamp, min_possible_timestamp);

        Ok((
            PoSBlockSolverInputData {
                stake_private_key,
                vrf_private_key,
                consensus_data,
                slot_infos,
                min_timestamp,
                max_timestamp,
                cur_tip_chain_trust,
                transactions,
                block_reward,
                last_used_block_timestamp_sender,
            },
            last_used_block_timestamp_receiver,
        ))
    }

    fn new_block_timestamp_for_non_pos(
        &self,
        prev_block_timestamp: BlockTimestamp,
    ) -> Result<BlockTimestamp, BlockProductionError> {
        // Note: here, the new block's timestamp is normally the parent's timestamp plus 1
        // (this behavior is historical and some tests depend on it); this is fine, because
        // PoW is not used outside of tests.
        // But some other tests need timestamps that are not in the past, this is handled
        // by the use_current_time_if_non_pos option.

        let mut new_block_timestamp = timestamp_add_secs(prev_block_timestamp, 1)?;

        if self.blockprod_config.use_current_time_if_non_pos {
            new_block_timestamp = std::cmp::max(
                new_block_timestamp,
                BlockTimestamp::from_time(self.time_getter.get_time()),
            );
        }

        Ok(new_block_timestamp)
    }

    async fn pull_block_solver_input_data_pow(
        &self,
        input_data: PoWGenerateBlockInputData,
        best_block_index: GenBlockIndex,
        next_height_pow_status: PoWStatus,
        transactions: TxData,
    ) -> Result<PoWBlockSolverInputData, BlockProductionError> {
        let best_block_id = best_block_index.block_id();
        let chain_config = Arc::clone(&self.chain_config);
        let next_block_height = best_block_index.block_height().next_height();

        let block_timestamp =
            self.new_block_timestamp_for_non_pos(best_block_index.block_timestamp())?;

        let (consensus_data, block_reward) = self
            .chainstate_handle
            .call(move |cs| -> Result<_, BlockProductionError> {
                let (consensus_data, block_reward) = generate_pow_consensus_data_and_reward(
                    &chain_config,
                    &best_block_index,
                    block_timestamp,
                    &next_height_pow_status,
                    make_ancestor_getter(cs),
                    input_data,
                    next_block_height,
                )
                .map_err(ConsensusCreationError::MiningError)?;

                Ok((consensus_data, block_reward))
            })
            .await??;

        let bits = consensus_data.bits();
        let (block_header, block_body) = self
            .prepare_block(
                best_block_id,
                block_reward,
                block_timestamp,
                ConsensusData::PoW(Box::new(consensus_data)),
                transactions,
                false,
            )
            .await?;

        Ok(PoWBlockSolverInputData {
            bits,
            block_header,
            block_body,
        })
    }

    async fn pull_block_solver_input_data_ignore_consensus(
        &self,
        best_block_index: GenBlockIndex,
        transactions: TxData,
    ) -> Result<IgnoreConsensusBlockSolverInputData, BlockProductionError> {
        let next_block_height = best_block_index.block_height().next_height();

        let block_timestamp =
            self.new_block_timestamp_for_non_pos(best_block_index.block_timestamp())?;

        let block_reward = generate_reward_ignore_consensus(&self.chain_config, next_block_height)?;

        let (block_header, block_body) = self
            .prepare_block(
                best_block_index.block_id(),
                block_reward,
                block_timestamp,
                ConsensusData::None,
                transactions,
                false,
            )
            .await?;

        Ok(IgnoreConsensusBlockSolverInputData {
            block_header,
            block_body,
        })
    }

    pub async fn pull_block_solver_input_data(
        &self,
        best_block_index: GenBlockIndex,
        input_data: GenerateBlockInputData,
        transactions: TxData,
    ) -> Result<
        (
            BlockSolverInputData,
            /*last_used_block_timestamp_for_pos_receiver:*/
            Option<watch::Receiver<BlockTimestamp>>,
        ),
        BlockProductionError,
    > {
        let next_block_height = best_block_index.block_height().next_height();
        let required_consensus =
            self.chain_config.consensus_upgrades().consensus_status(next_block_height);

        let (solver_data, last_used_block_timestamp_for_pos_receiver) = {
            let best_block_index = best_block_index.clone();

            match (required_consensus, input_data) {
                (
                    // Note: the PoSStatus is ignored here, because we don't yet know the actual height at which the
                    // new block will appear.
                    RequiredConsensus::PoS(_pos_status),
                    GenerateBlockInputData::PoS(pos_input_data),
                ) => {
                    let (solver_data, last_used_block_timestamp_for_pos_receiver) = self
                        .pull_block_solver_input_data_pos(
                            *pos_input_data,
                            best_block_index,
                            transactions,
                        )
                        .await?;

                    (
                        BlockSolverInputData::PoS(solver_data),
                        Some(last_used_block_timestamp_for_pos_receiver),
                    )
                }
                (
                    RequiredConsensus::PoW(pow_status),
                    GenerateBlockInputData::PoW(pow_input_data),
                ) => {
                    let solver_data = self
                        .pull_block_solver_input_data_pow(
                            *pow_input_data,
                            best_block_index,
                            pow_status,
                            transactions,
                        )
                        .await?;
                    (BlockSolverInputData::PoW(solver_data), None)
                }
                (RequiredConsensus::IgnoreConsensus, GenerateBlockInputData::None) => {
                    let solver_data = self
                        .pull_block_solver_input_data_ignore_consensus(
                            best_block_index,
                            transactions,
                        )
                        .await?;
                    (BlockSolverInputData::IgnoreConsensus(solver_data), None)
                }
                (RequiredConsensus::PoS(_), GenerateBlockInputData::PoW(_)) => Err(
                    ConsensusCreationError::StakingError(ConsensusPoSError::PoWInputDataProvided),
                )?,
                (RequiredConsensus::PoS(_), GenerateBlockInputData::None) => Err(
                    ConsensusCreationError::StakingError(ConsensusPoSError::NoInputDataProvided),
                )?,
                (RequiredConsensus::PoW(_), GenerateBlockInputData::PoS(_)) => Err(
                    ConsensusCreationError::MiningError(ConsensusPoWError::PoSInputDataProvided),
                )?,
                (RequiredConsensus::PoW(_), GenerateBlockInputData::None) => Err(
                    ConsensusCreationError::MiningError(ConsensusPoWError::NoInputDataProvided),
                )?,
                (RequiredConsensus::IgnoreConsensus, GenerateBlockInputData::PoS(_)) => {
                    Err(BlockProductionError::PoSInputDataProvidedWhenIgnoringConsensus)?
                }
                (RequiredConsensus::IgnoreConsensus, GenerateBlockInputData::PoW(_)) => {
                    Err(BlockProductionError::PoWInputDataProvidedWhenIgnoringConsensus)?
                }
            }
        };

        Ok((solver_data, last_used_block_timestamp_for_pos_receiver))
    }

    pub fn spawn_block_solver(
        &self,
        input_data: BlockSolverInputData,
        stop_flag: Arc<RelaxedAtomicBool>,
        ended_sender: std::sync::mpsc::Sender<()>,
        result_sender: oneshot::Sender<Result<BlockSolverOutputData, BlockProductionError>>,
    ) -> Result<(), BlockProductionError> {
        self.mining_thread_pool.spawn({
            let chain_config = Arc::clone(&self.chain_config);

            move || {
                let _ended_sender = OnceDestructor::new(move || {
                    // This can fail if the caller exited before the solver thread finished
                    let _ = ended_sender.send(());
                });

                let solver_result = solve_block(&chain_config, input_data, stop_flag)
                    .map_err(BlockProductionError::FailedConsensusInitialization);

                // This can fail if the caller exited before the solver thread finished
                let _ = result_sender.send(solver_result);
            }
        });

        Ok(())
    }

    pub async fn finalize_block(
        &self,
        data: BlockSolverOutputData,
    ) -> Result<Block, BlockProductionError> {
        let (signed_block_header, block_body) = match data {
            BlockSolverOutputData::PoS(data) => self.finalize_block_for_pos(data).await?,
            BlockSolverOutputData::NonPoS(NonPoSBlockSolverOutputData {
                block_header,
                block_body,
            }) => (block_header, block_body),
        };

        Ok(Block::new_from_header(signed_block_header, block_body)?)
    }

    async fn finalize_block_for_pos(
        &self,
        data: PoSBlockSolverOutputData,
    ) -> Result<(SignedBlockHeader, BlockBody), BlockProductionError> {
        let PoSPartialConsensusData {
            kernel_inputs,
            kernel_witness,
            pool_id,
        } = data.consensus_data;

        let consensus_data = PoSData::new(
            kernel_inputs,
            kernel_witness,
            pool_id,
            data.vrf_data,
            data.target,
        );

        let (block_header, block_body) = self
            .prepare_block(
                data.parent_id,
                data.block_reward,
                data.found_timestamp,
                ConsensusData::PoS(Box::new(consensus_data)),
                data.transactions,
                true,
            )
            .await?;

        let signed_block_header = data
            .stake_private_key
            .sign_message(&block_header.encode(), randomness::make_true_rng())
            .map_err(|_| {
                ConsensusCreationError::StakingError(ConsensusPoSError::FailedToSignBlockHeader)
            })
            .map(BlockHeaderSignatureData::new)
            .map(BlockHeaderSignature::HeaderSignature)
            .map(|signed_data| block_header.clone().with_signature(signed_data))?;

        Ok((signed_block_header, block_body))
    }
}

#[derive(Debug, Clone)]
pub enum BlockSolverInputData {
    PoS(PoSBlockSolverInputData),
    PoW(PoWBlockSolverInputData),
    IgnoreConsensus(IgnoreConsensusBlockSolverInputData),
}

impl BlockSolverInputData {
    pub fn is_pos(&self) -> bool {
        match self {
            BlockSolverInputData::PoS { .. } => true,
            BlockSolverInputData::PoW(_) | BlockSolverInputData::IgnoreConsensus(_) => false,
        }
    }
}

pub struct PoSTmpSlotInfo {
    parent_id: Id<GenBlock>,
    parent_timestamp: BlockTimestamp,
    parent_height: BlockHeight,
    parent_chain_trust: Uint256,
    target: Uint256,
    pos_chain_config: PoSChainConfig,
    epoch_index: EpochIndex,
    sealed_epoch_randomness: PoSRandomness,
}

/// Obtain information required for staking using given block as the parent.
// Note/TODO: this function is called in a loop that goes through block's parents.
// But it itself calls `calculate_target_required_from_block_index` that also iterates over block's parents,
// so the caller has quadratic complexity with respect to block index load calls. This can be optimized by
// pre-loading the required amount of block indices into memory. But also note that:
// 1) LMDB is already memory-mapped, so pre-loading indices into memory might not have that big of effect.
// 2) The number of parents traversed by the caller won't be big normally.
fn obtain_pos_slot_info(
    chain_config: &ChainConfig,
    chainstate: &dyn ChainstateInterface,
    parent_index: &GenBlockIndex,
) -> Result<Option<PoSTmpSlotInfo>, BlockProductionError> {
    let next_block_height = parent_index.block_height().next_height();

    let required_consensus = chain_config.consensus_upgrades().consensus_status(next_block_height);

    match required_consensus {
        RequiredConsensus::PoS(pos_status) => {
            let target = calculate_target_required_from_block_index(
                chain_config,
                &pos_status,
                parent_index,
                make_ancestor_getter(chainstate),
            )
            .and_then(compact_target_to_target)
            .map_err(ConsensusCreationError::StakingError)?;
            let pos_chain_config = pos_status.get_chain_config().clone();
            let epoch_index = chain_config.epoch_index_from_height(&next_block_height);
            let sealed_epoch_randomness =
                get_sealed_epoch_randomness(chain_config, chainstate, next_block_height)?;

            Ok(Some(PoSTmpSlotInfo {
                parent_id: parent_index.block_id(),
                parent_timestamp: parent_index.block_timestamp(),
                parent_height: parent_index.block_height(),
                parent_chain_trust: parent_index.chain_trust(),
                target,
                pos_chain_config,
                epoch_index,
                sealed_epoch_randomness,
            }))
        }
        RequiredConsensus::PoW(_) | RequiredConsensus::IgnoreConsensus => Ok(None),
    }
}

/// Find possible slots (i.e. parents) for a new block, given a minimum timestamp and assuming that
/// the maximum timestamp is bigger than the tip's.
/// Always return a non-empty set or an error.
fn collect_pos_slot_infos(
    chainstate: &dyn ChainstateInterface,
    pool_id: &PoolId,
    min_timestamp: BlockTimestamp,
    best_block_index: GenBlockIndex,
) -> Result<PoSSlotInfosByParentTS, BlockProductionError> {
    let chain_config = chainstate.get_chain_config();
    let best_block_height = best_block_index.block_height();
    let mut tmp_infos = Vec::new();
    let mut next_gen_block_index = best_block_index;

    loop {
        let tmp_info = obtain_pos_slot_info(chain_config, chainstate, &next_gen_block_index)?;
        let tmp_info = if let Some(tmp_info) = tmp_info {
            tmp_info
        } else {
            break;
        };

        tmp_infos.push(tmp_info);

        if min_timestamp > next_gen_block_index.block_timestamp() {
            // We've already seen a parent with the timestamp strictly less than min_timestamp, so we can stop now.
            break;
        }

        let block_index = match next_gen_block_index {
            GenBlockIndex::Block(block_index) => block_index,
            GenBlockIndex::Genesis(_) => {
                break;
            }
        };

        match block_index.block_header().consensus_data() {
            ConsensusData::PoS(pos_data) => {
                if pos_data.stake_pool_id() == pool_id {
                    // We've found a parent block that was created by this pool. We can't go below it,
                    // or else we'll be staking twice for the same timestamp.
                    break;
                }
            }
            ConsensusData::PoW(_) | ConsensusData::None => {
                break;
            }
        }

        next_gen_block_index =
            get_existing_gen_block_index(chainstate, block_index.prev_block_id())?;
    }

    // Note: tmp_infos are sorted by height backwards.
    let min_parent_height = tmp_infos.last().ok_or_else(|| {
        // We can only get here, if obtain_pos_slot_info has returned None for best_block_index.
        debug_assert!(false, "Collected slot info is empty, which means that the best block has non-PoS consensus type");
        BlockProductionError::InvariantBrokenExpectingPoSConsensusType
    })?.parent_height;

    let pool_balances =
        get_pool_balances_at_heights(chainstate, min_parent_height, best_block_height, pool_id)?
            .collect::<BTreeMap<_, _>>();

    let mut infos = BTreeSet::new();

    for tmp_info in tmp_infos {
        if let Some(balances) = pool_balances.get(&tmp_info.parent_height) {
            infos.insert(PoSSlotInfoCmpByParentTS(PoSSlotInfoExt {
                slot_info: PoSSlotInfo {
                    parent_timestamp: tmp_info.parent_timestamp,
                    parent_chain_trust: tmp_info.parent_chain_trust,
                    target: tmp_info.target,
                    pos_chain_config: tmp_info.pos_chain_config,
                    epoch_index: tmp_info.epoch_index,
                    sealed_epoch_randomness: tmp_info.sealed_epoch_randomness,
                    staker_balance: balances.staker_balance(),
                    total_balance: balances.total_balance(),
                },
                parent_id: tmp_info.parent_id,
            }));
        }
    }

    if infos.is_empty() {
        debug_assert!(
            false,
            "Couldn't find any possible parents for staking with pool {pool_id}"
        );
        Err(BlockProductionError::InvariantBrokenNoParentsForPoS(
            *pool_id,
        ))
    } else {
        Ok(infos)
    }
}

#[derive(Debug, Clone)]
struct PoSSlotInfoExt {
    slot_info: PoSSlotInfo,
    parent_id: Id<GenBlock>,
}

impl AsRef<PoSSlotInfo> for PoSSlotInfoExt {
    fn as_ref(&self) -> &PoSSlotInfo {
        &self.slot_info
    }
}

type PoSSlotInfosByParentTS = BTreeSet<PoSSlotInfoCmpByParentTS<PoSSlotInfoExt>>;

#[derive(Debug, Clone)]
pub struct PoSBlockSolverInputData {
    stake_private_key: PrivateKey,
    vrf_private_key: VRFPrivateKey,

    consensus_data: PoSPartialConsensusData,

    slot_infos: PoSSlotInfosByParentTS,

    cur_tip_chain_trust: Uint256,

    min_timestamp: BlockTimestamp,
    max_timestamp: BlockTimestamp,

    transactions: TxData,
    block_reward: BlockReward,

    last_used_block_timestamp_sender: watch::Sender<BlockTimestamp>,
}

#[derive(Debug, Clone)]
pub struct PoWBlockSolverInputData {
    // The required target.
    bits: Compact,

    block_header: BlockHeader,
    // Note: the block body is not needed by `solve_block`, but we have to include it here,
    // to be able to put it to NonPoSBlockSolverOutputData later.
    block_body: BlockBody,
}

#[derive(Debug, Clone)]
pub struct IgnoreConsensusBlockSolverInputData {
    block_header: BlockHeader,
    // Note: same as in the PoW case, this is only needed here to be able to put it to NonPoSBlockSolverOutputData later.
    block_body: BlockBody,
}

pub fn solve_block(
    chain_config: &ChainConfig,
    input_data: BlockSolverInputData,
    stop_flag: Arc<RelaxedAtomicBool>,
) -> Result<BlockSolverOutputData, ConsensusCreationError> {
    match input_data {
        BlockSolverInputData::PoS(input_data) => {
            let stake_result = stake(
                chain_config,
                &input_data.consensus_data.pool_id,
                &input_data.vrf_private_key,
                input_data.slot_infos.iter(),
                input_data.min_timestamp,
                input_data.max_timestamp,
                &input_data.cur_tip_chain_trust,
                Some(&input_data.last_used_block_timestamp_sender),
                Some(stop_flag),
            )?;

            match stake_result {
                StakeResult::Success {
                    slot_info,
                    timestamp,
                    vrf_data,
                } => Ok(BlockSolverOutputData::PoS(PoSBlockSolverOutputData {
                    found_timestamp: timestamp,
                    vrf_data,
                    consensus_data: input_data.consensus_data,
                    target: slot_info.slot_info.target.into(),
                    parent_id: slot_info.parent_id,
                    stake_private_key: input_data.stake_private_key,
                    block_reward: input_data.block_reward,
                    transactions: input_data.transactions,
                })),
                StakeResult::Failed => Err(ConsensusCreationError::StakingFailed),
                StakeResult::Stopped => Err(ConsensusCreationError::StakingStopped),
            }
        }
        BlockSolverInputData::PoW(PoWBlockSolverInputData {
            bits,
            mut block_header,
            block_body,
        }) => {
            let mine_result = mine(&mut block_header, u128::MAX, bits, stop_flag)?;

            match mine_result {
                MiningResult::Success => {
                    Ok(BlockSolverOutputData::NonPoS(NonPoSBlockSolverOutputData {
                        block_header: block_header.with_no_signature(),
                        block_body,
                    }))
                }
                MiningResult::Failed => Err(ConsensusCreationError::MiningFailed),
                MiningResult::Stopped => Err(ConsensusCreationError::MiningStopped),
            }
        }
        BlockSolverInputData::IgnoreConsensus(IgnoreConsensusBlockSolverInputData {
            block_header,
            block_body,
        }) => Ok(BlockSolverOutputData::NonPoS(NonPoSBlockSolverOutputData {
            block_header: block_header.with_no_signature(),
            block_body,
        })),
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum BlockSolverOutputData {
    PoS(PoSBlockSolverOutputData),
    NonPoS(NonPoSBlockSolverOutputData),
}

#[derive(Debug, Clone)]
pub struct PoSBlockSolverOutputData {
    found_timestamp: BlockTimestamp,
    vrf_data: VRFReturn,

    consensus_data: PoSPartialConsensusData,
    target: Compact,
    parent_id: Id<GenBlock>,

    stake_private_key: PrivateKey,
    block_reward: BlockReward,
    transactions: TxData,
}

#[derive(Debug, Clone)]
pub struct NonPoSBlockSolverOutputData {
    block_header: SignedBlockHeader,
    block_body: BlockBody,
}
