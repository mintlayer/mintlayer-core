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

use std::sync::Arc;

use chainstate_types::pos_randomness::PoSRandomness;
use crypto::{
    key::PrivateKey,
    vrf::{VRFPrivateKey, VRFReturn},
};
use logging::log;
use serialization::Encode;
use tokio::sync::{oneshot, watch};

use ::utils::{atomics::RelaxedAtomicBool, once_destructor::OnceDestructor};
use chainstate::GenBlockIndex;
use common::{
    address::Address,
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
        Block, ChainConfig, GenBlock, PoSChainConfig, PoSStatus, PoWStatus, RequiredConsensus,
    },
    primitives::{Amount, Compact, Id},
};
use consensus::{
    calculate_target_required_from_block_index, find_timestamp_for_staking,
    generate_pos_consensus_data_and_reward, generate_pow_consensus_data_and_reward,
    generate_reward_ignore_consensus, mine, ConsensusCreationError, ConsensusPoSError,
    ConsensusPoWError, GenerateBlockInputData, MiningResult, PoSGenerateBlockInputData,
    PoSPartialConsensusData, PoWGenerateBlockInputData, StakeResult,
};

use crate::BlockProductionError;

use super::{
    utils::{
        self, get_pool_staker_balance, get_pool_total_balance, get_sealed_epoch_randomness,
        make_ancestor_getter, timestamp_add_secs,
    },
    BlockProduction, TxData,
};

impl BlockProduction {
    async fn pull_block_solver_input_data_pos(
        &self,
        input_data: PoSGenerateBlockInputData,
        best_block_index: GenBlockIndex,
        next_height_pos_status: PoSStatus,
        transactions: TxData,
    ) -> Result<(PoSBlockSolverInputData, watch::Receiver<BlockTimestamp>), BlockProductionError>
    {
        let best_block_id = best_block_index.block_id();
        let chain_config = Arc::clone(&self.chain_config);
        let next_block_height = best_block_index.block_height().next_height();
        let last_used_block_timestamp_for_pos =
            self.get_last_used_block_timestamp_for_pos_data(&input_data);

        let current_timestamp = BlockTimestamp::from_time(self.time_getter.get_time());
        let min_timestamp = {
            let prev_timestamp = std::cmp::max(
                last_used_block_timestamp_for_pos.unwrap_or(BlockTimestamp::from_int_seconds(0)),
                best_block_index.block_timestamp(),
            );

            timestamp_add_secs(prev_timestamp, 1)?
        };
        let max_timestamp = {
            let max_offset = chain_config.max_future_block_time_offset().as_secs();
            timestamp_add_secs(current_timestamp, max_offset)?
        };

        if min_timestamp > max_timestamp {
            return Err(BlockProductionError::TryAgainLater);
        }

        let (last_used_block_timestamp_sender, last_used_block_timestamp_receiver) =
            watch::channel(min_timestamp);

        let stake_private_key = input_data.stake_private_key().clone();
        let vrf_private_key = input_data.vrf_private_key().clone();
        let (consensus_data, block_reward) =
            generate_pos_consensus_data_and_reward(input_data, randomness::make_true_rng())?;

        let pool_id = consensus_data.pool_id;
        let epoch_index = chain_config.epoch_index_from_height(&next_block_height);
        let pos_chain_config = next_height_pos_status.get_chain_config().clone();

        let (sealed_epoch_randomness, target, total_balance, staker_balance) = self
            .chainstate_handle
            .call(move |cs| -> Result<_, BlockProductionError> {
                let sealed_epoch_randomness =
                    get_sealed_epoch_randomness(&chain_config, cs, next_block_height)?;

                let target = calculate_target_required_from_block_index(
                    &chain_config,
                    &next_height_pos_status,
                    &best_block_index,
                    make_ancestor_getter(cs),
                )
                .map_err(ConsensusCreationError::StakingError)?;

                let total_balance = get_pool_total_balance(cs, &pool_id)?;
                let staker_balance = get_pool_staker_balance(cs, &pool_id)?;

                #[cfg(debug_assertions)]
                {
                    let pool_balances = utils::get_pool_balances_at_height(
                        cs,
                        next_block_height.prev_height().expect("new block height can't be zero"),
                        &pool_id,
                    )?;

                    assert_eq!(total_balance, pool_balances.total_balance());
                    assert_eq!(staker_balance, pool_balances.staker_balance());
                }

                Ok((
                    sealed_epoch_randomness,
                    target,
                    total_balance,
                    staker_balance,
                ))
            })
            .await??;

        Ok((
            PoSBlockSolverInputData {
                stake_private_key,
                vrf_private_key,
                consensus_data,
                parent_id: best_block_id,
                target,
                pos_chain_config,
                epoch_index,
                sealed_epoch_randomness,
                staker_balance,
                total_balance,
                min_timestamp,
                max_timestamp,
                transactions,
                block_reward,
                last_used_block_timestamp_sender,
            },
            last_used_block_timestamp_receiver,
        ))
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

        // Note: here, the new block's timestamp is always the parent's timestamp plus 1
        // (this behavior is historical amd some tests depend on it); this is fine, because
        // PoW is not used outside of tests.
        let block_timestamp = timestamp_add_secs(best_block_index.block_timestamp(), 1)?;

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

        // Note: here, the new block's timestamp is always the parent's timestamp plus 1
        // (this behavior is historical amd some tests depend on it); this is fine, because
        // this type of consensus is not used outside of tests.
        let block_timestamp = timestamp_add_secs(best_block_index.block_timestamp(), 1)?;

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
                    RequiredConsensus::PoS(pos_status),
                    GenerateBlockInputData::PoS(pos_input_data),
                ) => {
                    let (solver_data, last_used_block_timestamp_for_pos_receiver) = self
                        .pull_block_solver_input_data_pos(
                            *pos_input_data,
                            best_block_index,
                            pos_status,
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
                let solver_result = solve_block(&chain_config, input_data, stop_flag)
                    .map_err(BlockProductionError::FailedConsensusInitialization);

                let _ended_sender = OnceDestructor::new(move || {
                    // This can fail if the function exited before the mining thread finished
                    let _send_whether_ended = ended_sender.send(());
                });

                result_sender
                    .send(solver_result)
                    .expect("Failed to send block header back to main thread");
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
        } = data.input_data.consensus_data;

        let consensus_data = PoSData::new(
            kernel_inputs,
            kernel_witness,
            pool_id,
            data.vrf_data,
            data.input_data.target,
        );

        let (block_header, block_body) = self
            .prepare_block(
                data.input_data.parent_id,
                data.input_data.block_reward,
                data.found_timestamp,
                ConsensusData::PoS(Box::new(consensus_data)),
                data.input_data.transactions,
                true,
            )
            .await?;

        let signed_block_header = data
            .input_data
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

#[derive(Debug, Clone)]
pub struct PoSBlockSolverInputData {
    /// The private key of the staker.
    stake_private_key: PrivateKey,
    /// The VRF private key.
    vrf_private_key: VRFPrivateKey,

    consensus_data: PoSPartialConsensusData,

    parent_id: Id<GenBlock>,

    // Note: target, pos_chain_config, the epoch data and balances depend on parent_id.
    target: Compact,
    pos_chain_config: PoSChainConfig,

    /// The epoch index of the height of the new block
    epoch_index: EpochIndex,
    /// The sealed epoch randomness (i.e used in producing VRF data)
    sealed_epoch_randomness: PoSRandomness,

    /// The portion of the pool balance that belongs to the staker
    staker_balance: Amount,
    /// The current total balance of the stake pool.
    total_balance: Amount,

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
            let stake_result = stake(chain_config, &input_data)?;

            match stake_result {
                StakeResult::Success {
                    found_timestamp,
                    vrf_data,
                } => Ok(BlockSolverOutputData::PoS(PoSBlockSolverOutputData {
                    input_data,
                    found_timestamp,
                    vrf_data,
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

pub fn stake(
    chain_config: &ChainConfig,
    input_data: &PoSBlockSolverInputData,
) -> Result<StakeResult, ConsensusPoSError> {
    let final_supply = chain_config
        .final_supply()
        .ok_or(ConsensusPoSError::FiniteTotalSupplyIsRequired)?;

    log::debug!(
        "Search for a valid block ({}..{}), pool_id: {}",
        input_data.min_timestamp,
        input_data.max_timestamp,
        Address::new(chain_config, input_data.consensus_data.pool_id)
            .expect("Pool id to address cannot fail")
    );

    if let Some((found_timestamp, vrf_data)) = find_timestamp_for_staking(
        final_supply,
        &input_data.pos_chain_config,
        input_data.target,
        input_data.min_timestamp,
        input_data.max_timestamp,
        &input_data.sealed_epoch_randomness,
        input_data.epoch_index,
        input_data.staker_balance,
        input_data.total_balance,
        &input_data.vrf_private_key,
        &mut randomness::make_true_rng(),
    )? {
        log::info!(
            "Valid block found, timestamp: {}, pool_id: {}",
            found_timestamp,
            input_data.consensus_data.pool_id
        );

        let _ = input_data.last_used_block_timestamp_sender.send(found_timestamp);

        Ok(StakeResult::Success {
            found_timestamp,
            vrf_data,
        })
    } else {
        let _ = input_data.last_used_block_timestamp_sender.send(input_data.max_timestamp);
        Ok(StakeResult::Failed)
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
    input_data: PoSBlockSolverInputData,
    found_timestamp: BlockTimestamp,
    vrf_data: VRFReturn,
}

#[derive(Debug, Clone)]
pub struct NonPoSBlockSolverOutputData {
    block_header: SignedBlockHeader,
    block_body: BlockBody,
}
