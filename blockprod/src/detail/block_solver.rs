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

use std::{collections::BTreeSet, sync::Arc};

use chainstate_types::pos_randomness::PoSRandomness;
use crypto::{
    key::PrivateKey,
    vrf::{VRFPrivateKey, VRFReturn},
};
use itertools::Itertools;
use serialization::Encode;
use tokio::sync::{oneshot, watch};

use ::utils::{atomics::RelaxedAtomicBool, once_destructor::OnceDestructor};
use chainstate::{chainstate_interface::ChainstateInterface, GenBlockIndex, NonZeroPoolBalances};
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
    primitives::{Compact, Id},
    Uint256,
};
use consensus::{
    calculate_target_required_from_block_index, compact_target_to_target,
    generate_pos_consensus_data_and_reward, generate_pow_consensus_data_and_reward,
    generate_reward_ignore_consensus, mine, stake, ConsensusCreationError, ConsensusPoSError,
    ConsensusPoWError, GenerateBlockInputData, MiningResult, PoSBlockCandidateInfo,
    PoSBlockCandidateInfoCmpByParentTS, PoSGenerateBlockInputData, PoSPartialConsensusData,
    PoWGenerateBlockInputData, StakeResult,
};

use crate::BlockProductionError;

use super::{
    utils::{
        get_block_tree_top_starting_from_timestamp, get_existing_gen_block_index,
        get_min_height_with_allowed_reorg, get_sealed_epoch_randomness,
        get_stake_pool_balances_at_tip, get_stake_pool_balances_for_tree, is_block_in_main_chain,
        make_ancestor_getter, timestamp_add_secs, try_connect_block_trees,
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

        let stake_private_key = input_data.stake_private_key().clone();
        let vrf_private_key = input_data.vrf_private_key().clone();
        let (consensus_data, block_reward) =
            generate_pos_consensus_data_and_reward(input_data, randomness::make_true_rng())?;

        let pool_id = consensus_data.pool_id;

        let candidate_infos = self
            .chainstate_handle
            .call(move |cs| -> Result<_, BlockProductionError> {
                collect_pos_candidate_infos(cs, &pool_id, min_timestamp, best_block_index)
            })
            .await??;

        let first_candidate_info = candidate_infos.first().expect("parents map must be non-empty");
        let earliest_parent_timestamp = first_candidate_info.0.parent_timestamp;
        let min_possible_timestamp = timestamp_add_secs(earliest_parent_timestamp, 1)?;
        let min_timestamp = std::cmp::max(min_timestamp, min_possible_timestamp);

        Ok((
            PoSBlockSolverInputData {
                stake_private_key,
                vrf_private_key,
                consensus_data,
                candidate_infos,
                min_timestamp,
                max_timestamp,
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

pub struct PoSTmpBlockCandidateInfo {
    parent_id: Id<GenBlock>,
    parent_timestamp: BlockTimestamp,
    parent_chain_trust: Uint256,
    target: Uint256,
    pos_chain_config: PoSChainConfig,
    epoch_index: EpochIndex,
    sealed_epoch_randomness: PoSRandomness,
}

/// Obtain information required for staking using given block as the parent.
// Note/TODO: this function is called in a loop that goes through block's parents.
// But it itself calls `calculate_target_required_from_block_index` that also iterates over block's parents,
// so the caller has quadratic complexity with respect to block index load calls. And although
// LMDB is itself memory-mapped, out storage has extra overhead of memory allocations when searching
// for the key. So it may make sense to introduce something like a BlockIndexCache, which would
// hold already collected block indices, and pass it here (note that this will require passing
// this cache object to ChainstateInterface::get_ancestor as well).
fn obtain_pos_candidate_info(
    chain_config: &ChainConfig,
    chainstate: &dyn ChainstateInterface,
    parent_index: &GenBlockIndex,
) -> Result<Option<PoSTmpBlockCandidateInfo>, BlockProductionError> {
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

            Ok(Some(PoSTmpBlockCandidateInfo {
                parent_id: parent_index.block_id(),
                parent_timestamp: parent_index.block_timestamp(),
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

fn make_pos_candidate_info(
    tmp_info: PoSTmpBlockCandidateInfo,
    pool_balances: NonZeroPoolBalances,
) -> PoSBlockCandidateInfo {
    PoSBlockCandidateInfo {
        parent_id: tmp_info.parent_id,
        parent_timestamp: tmp_info.parent_timestamp,
        parent_chain_trust: tmp_info.parent_chain_trust,
        target: tmp_info.target,
        pos_chain_config: tmp_info.pos_chain_config,
        epoch_index: tmp_info.epoch_index,
        sealed_epoch_randomness: tmp_info.sealed_epoch_randomness,
        staker_balance: pool_balances.staker_balance(),
        total_balance: pool_balances.total_balance(),
    }
}

/// Find possible parents for a new block, given a minimum timestamp and assuming that
/// the maximum timestamp is bigger than the tip's.
/// Always return a non-empty set or an error.
fn collect_pos_candidate_infos(
    chainstate: &dyn ChainstateInterface,
    pool_id: &PoolId,
    min_timestamp: BlockTimestamp,
    best_block_index: GenBlockIndex,
) -> Result<PoSBlockCandidateInfosByParentTS, BlockProductionError> {
    let chain_config = chainstate.get_chain_config();
    let mut infos = BTreeSet::new();

    if min_timestamp > best_block_index.block_timestamp() || best_block_index.is_genesis() {
        if let Some(tmp_info) =
            obtain_pos_candidate_info(chain_config, chainstate, &best_block_index)?
        {
            if let Some(pool_balances) = get_stake_pool_balances_at_tip(chainstate, pool_id)? {
                infos.insert(PoSBlockCandidateInfoCmpByParentTS(make_pos_candidate_info(
                    tmp_info,
                    pool_balances,
                )));
            }
        }
    } else {
        // Obtain all blocks with timestamps bigger than or equal to the minimum.
        let block_trees = get_block_tree_top_starting_from_timestamp(
            chainstate,
            min_timestamp,
            chainstate::BlockValidity::Ok,
        )?;

        // Now we need to obtain pool balances; since get_stake_pool_balances_for_tree needs
        // a single tree, we need to connect the roots in `block_trees` to a single common root.
        // This is an expensive operation, involving disconnecting/re-connecting blocks in memory,
        // so we don't want to go too deep; stale chains that don't connect to the mainchain
        // at or above the specified minimum height will be skipped by the logic below.
        // TODO: "min_height_with_allowed_reorg" is 1000 blocks below the tip, we probably don't
        // need to go that deep.
        let min_height = get_min_height_with_allowed_reorg(chainstate)?;
        let block_trees = try_connect_block_trees(chainstate, block_trees, min_height)?;

        let mainchain_tree_root = itertools::process_results(
            block_trees.roots().map(
                |(block_id, _)| -> Result<(Id<Block>, bool), BlockProductionError> {
                    let is_in_mainchain = is_block_in_main_chain(chainstate, block_id.into())?;
                    Ok((*block_id, is_in_mainchain))
                },
            ),
            |iter| {
                iter.filter_map(move |(block_id, is_in_mainchain)| is_in_mainchain.then_some(block_id)).exactly_one()
                .map_err(|err| {
                    BlockProductionError::InvariantBrokenUnexpectedNumberOfMainchainRootsInBlockTree(
                        err.to_string(),
                    )
                })
            },
        )??;

        // Now choose the tree that contains the mainchain.
        // Note: if there are stale chains that start directly from the genesis, this logic
        // will always skip them. This is not a realistic situation though, so we don't care.
        let block_tree = block_trees.into_single_tree(&mainchain_tree_root).map_err(|err| {
            BlockProductionError::InvariantBrokenCantObtainSingleBlockTree(err.to_string())
        })?;

        // try_connect_block_trees may have extended the tree too much (e.g. it was trying to connect
        // two branches but the height limit has been reached). If we pass it to get_stake_pool_balances_for_tree
        // as is, we may be performing redundant reorgs to heights that we don't care about.
        // To avoid doing so, iterate over the tree upwards, skipping redundant root nodes.
        let block_tree_ref = {
            let mut block_tree_ref = block_tree.as_ref();

            loop {
                // If a root has more than one child, then it's needed to be able to reorg to a stale chain,
                // so we can't skip it.
                if let Some(single_child_node_id) =
                    block_tree_ref.get_single_child_of(block_tree_ref.root_node_id())?
                {
                    let child_block_index = block_tree_ref.get_block_index(single_child_node_id)?;

                    // The single child of the root node is already below the minimum timestamp;
                    // this means that the root is useless.
                    if child_block_index.block_timestamp() < min_timestamp {
                        block_tree_ref = block_tree_ref.subtree(single_child_node_id)?;
                        continue;
                    }
                }

                break;
            }

            block_tree_ref
        };

        // Obtain pool balances. Note that obtaining balances for the parent of block_tree's root may
        // not be needed, so we check for this.
        let include_tree_root_parent =
            block_tree_ref.root_block_index()?.block_timestamp() >= min_timestamp;
        let pool_balances = get_stake_pool_balances_for_tree(
            chainstate,
            &[*pool_id],
            block_tree_ref,
            include_tree_root_parent,
        )?;

        let get_balances = |block_id: &Id<GenBlock>| {
            pool_balances.get(block_id).and_then(|balances| balances.get(pool_id))
        };

        // To obtain the parents info, we need to iterate from the tree's leaves down to the root,
        // while checking if any of the blocks was produced by our pool.

        // First, obtain the set of leaves.
        // TODO: we could store the leaves in the tree itself when constructing it.
        let mut leaves = Vec::new();
        for node_id in block_tree_ref.all_child_node_ids_iter() {
            if !block_tree_ref.has_children(node_id)? {
                leaves.push(node_id);
            }
        }

        let mut seen_nodes = BTreeSet::new();
        let mut root_reached = false;

        for leaf in leaves {
            let mut cur_node_id = leaf;

            loop {
                if seen_nodes.contains(&cur_node_id) {
                    break;
                }

                seen_nodes.insert(cur_node_id);

                let cur_block_index = block_tree_ref.get_block_index(cur_node_id)?;

                let tmp_info = if let Some(tmp_info) = obtain_pos_candidate_info(
                    chain_config,
                    chainstate,
                    &GenBlockIndex::Block(cur_block_index.clone()),
                )? {
                    tmp_info
                } else {
                    break;
                };

                if let Some(pool_balances) = get_balances(cur_block_index.block_id().into()) {
                    infos.insert(PoSBlockCandidateInfoCmpByParentTS(make_pos_candidate_info(
                        tmp_info,
                        pool_balances.clone(),
                    )));
                } else {
                    break;
                };

                if min_timestamp > cur_block_index.block_timestamp() {
                    // We've already seen a parent with the timestamp strictly less than min_timestamp,
                    // it makes no sense to go deeper.
                    break;
                }

                match cur_block_index.block_header().consensus_data() {
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

                if let Some(parent_node_id) = block_tree_ref.get_parent(cur_node_id)? {
                    cur_node_id = parent_node_id;
                } else {
                    root_reached = true;
                    break;
                }
            }
        }

        // If we've reached the root node from any of the leaves, the parent of the root block
        // may be eligible too.
        if root_reached {
            let root_block_index = block_tree_ref.root_block_index()?;

            if root_block_index.block_timestamp() >= min_timestamp {
                let prev_block_id = root_block_index.prev_block_id();
                if let Some(pool_balances) = get_balances(prev_block_id) {
                    let prev_block_index = get_existing_gen_block_index(chainstate, prev_block_id)?;
                    if let Some(tmp_info) =
                        obtain_pos_candidate_info(chain_config, chainstate, &prev_block_index)?
                    {
                        infos.insert(PoSBlockCandidateInfoCmpByParentTS(make_pos_candidate_info(
                            tmp_info,
                            pool_balances.clone(),
                        )));
                    }
                }
            }
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

type PoSBlockCandidateInfosByParentTS = BTreeSet<PoSBlockCandidateInfoCmpByParentTS>;

#[derive(Debug, Clone)]
pub struct PoSBlockSolverInputData {
    stake_private_key: PrivateKey,
    vrf_private_key: VRFPrivateKey,

    consensus_data: PoSPartialConsensusData,

    candidate_infos: PoSBlockCandidateInfosByParentTS,


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
                input_data.candidate_infos.iter(),
                input_data.min_timestamp,
                input_data.max_timestamp,
                Some(&input_data.last_used_block_timestamp_sender),
                Some(stop_flag),
            )?;

            match stake_result {
                StakeResult::Success {
                    block_candidate_info,
                    timestamp,
                    vrf_data,
                } => Ok(BlockSolverOutputData::PoS(PoSBlockSolverOutputData {
                    found_timestamp: timestamp,
                    vrf_data,
                    consensus_data: input_data.consensus_data,
                    target: block_candidate_info.target.into(),
                    parent_id: block_candidate_info.parent_id,
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
