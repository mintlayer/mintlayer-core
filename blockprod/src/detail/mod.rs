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

mod helper;
pub mod job_manager;

use std::sync::Arc;

use chainstate::{chainstate_interface::ChainstateInterface, ChainstateHandle, PropertyQueryError};
use chainstate_types::{
    pos_randomness::PoSRandomness, BlockIndex, GenBlockIndex, GetAncestorError,
};
use common::{
    address::Address,
    chain::{
        block::{
            block_body::BlockBody,
            consensus_data::{PoSData, PoWData},
            signed_block_header::{BlockHeaderSignature, BlockHeaderSignatureData},
            timestamp::BlockTimestamp,
            BlockCreationError, BlockHeader, BlockReward, ConsensusData,
        },
        Block, ChainConfig, GenBlock, PoSStatus, PoWStatus, RequiredConsensus, SignedTransaction,
        Transaction,
    },
    primitives::{Amount, BlockHeight, Id, Idable},
    time_getter::TimeGetter,
};
use consensus::{
    find_timestamp_for_staking, generate_pos_consensus_data_and_reward,
    generate_pow_consensus_data_and_reward, generate_reward_ignore_consensus, mine,
    ConsensusCreationError, ConsensusPoSError, ConsensusPoWError, GenerateBlockInputData,
    MiningResult, PoSFinalizeBlockInputData, PoSGenerateBlockInputData, PoWGenerateBlockInputData,
    PosDataExt,
};
use crypto::ephemeral_e2e::{self, EndToEndPrivateKey};
use logging::log;
use mempool::{
    tx_accumulator::{DefaultTxAccumulator, PackingStrategy, TransactionAccumulator},
    MempoolHandle,
};
use p2p::P2pHandle;
use randomness::{make_true_rng, Rng};
use serialization::{Decode, Encode};
use tokio::sync::oneshot;

use crate::{
    config::BlockProdConfig,
    detail::job_manager::{JobKey, JobManagerHandle, JobManagerImpl},
    BlockProductionError,
};

use self::helper::Helper;

#[derive(Debug, Clone)]
pub enum TransactionsSource {
    Mempool,
    Provided(Vec<SignedTransaction>),
}

pub const JOBKEY_DEFAULT_LEN: usize = 32;

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct CustomId {
    data: Vec<u8>,
}

impl CustomId {
    pub fn new_from_entropy() -> Self {
        let mut rng = make_true_rng();

        Self {
            data: rng.gen::<[u8; JOBKEY_DEFAULT_LEN]>().into(),
        }
    }

    pub fn new_from_input_data(input_data: &GenerateBlockInputData) -> Self {
        match input_data {
            GenerateBlockInputData::PoS(pos_input_data) => Self {
                data: pos_input_data.stake_public_key().encode(),
            },
            GenerateBlockInputData::None | GenerateBlockInputData::PoW(_) => {
                Self::new_from_entropy()
            }
        }
    }

    pub fn new_from_pos_input_data(input_data: &PoSGenerateBlockInputData) -> Self {
        Self {
            data: input_data.stake_public_key().encode(),
        }
    }

    pub fn new_from_value(value: Vec<u8>) -> Self {
        Self { data: value }
    }
}

#[allow(dead_code)]
pub struct BlockProduction {
    chain_config: Arc<ChainConfig>,
    blockprod_config: Arc<BlockProdConfig>,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    time_getter: TimeGetter,
    job_manager_handle: JobManagerHandle,
    mining_thread_pool: Arc<slave_pool::ThreadPool>,
    p2p_handle: P2pHandle,
    e2e_encryption_key: ephemeral_e2e::EndToEndPrivateKey,
}

impl BlockProduction {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        blockprod_config: Arc<BlockProdConfig>,
        chainstate_handle: ChainstateHandle,
        mempool_handle: MempoolHandle,
        p2p_handle: P2pHandle,
        time_getter: TimeGetter,
        mining_thread_pool: Arc<slave_pool::ThreadPool>,
    ) -> Result<Self, BlockProductionError> {
        let job_manager_handle = Box::new(JobManagerImpl::new(Some(chainstate_handle.clone())));

        let mut rng = make_true_rng();

        let block_production = Self {
            chain_config,
            blockprod_config,
            chainstate_handle,
            mempool_handle,
            p2p_handle,
            time_getter,
            job_manager_handle,
            mining_thread_pool,
            e2e_encryption_key: EndToEndPrivateKey::new_from_rng(&mut rng),
        };

        Ok(block_production)
    }

    pub fn time_getter(&self) -> &TimeGetter {
        &self.time_getter
    }

    #[cfg(test)]
    fn set_job_manager(&mut self, job_manager_handle: JobManagerHandle) {
        self.job_manager_handle = job_manager_handle
    }

    pub async fn stop_all_jobs(&mut self) -> Result<usize, BlockProductionError> {
        self.job_manager_handle
            .stop_all_jobs()
            .await
            .map_err(BlockProductionError::JobManagerError)
    }

    pub async fn stop_job(&mut self, job_key: JobKey) -> Result<bool, BlockProductionError> {
        Ok(self.job_manager_handle.stop_job(job_key).await? == 1)
    }

    pub async fn update_last_used_block_timestamp(
        &self,
        custom_id: CustomId,
        last_used_block_timestamp: BlockTimestamp,
    ) -> Result<(), BlockProductionError> {
        self.job_manager_handle
            .update_last_used_block_timestamp(custom_id, last_used_block_timestamp)
            .await?;

        Ok(())
    }

    // FIXME: don't return PropertyQueryError
    fn ancestor_getter(
        cs: &dyn ChainstateInterface,
    ) -> impl Fn(&BlockIndex, BlockHeight) -> Result<GenBlockIndex, PropertyQueryError> + '_ {
        |block_index: &BlockIndex, ancestor_height: BlockHeight| {
            cs.get_ancestor(&block_index.clone().into_gen_block_index(), ancestor_height)
                .map_err(|_| {
                    PropertyQueryError::GetAncestorError(GetAncestorError::InvalidAncestorHeight {
                        block_height: block_index.block_height(),
                        ancestor_height,
                    })
                })
        }
    }

    async fn pull_consensus_data_pos(
        &self,
        input_data: PoSGenerateBlockInputData,
        pos_status: PoSStatus,
        prev_block_index: &GenBlockIndex,
        block_timestamp: BlockTimestamp,
    ) -> Result<(PoSData, BlockReward, PoSFinalizeBlockInputData), BlockProductionError> {
        let consensus_data = self
            .chainstate_handle
            .call({
                let chain_config = Arc::clone(&self.chain_config);
                let prev_block_index = prev_block_index.clone();

                move |cs| {
                    let block_height = prev_block_index.block_height().next_height();
                    let sealed_epoch_index = chain_config.sealed_epoch_index(&block_height);

                    let sealed_epoch_randomness = sealed_epoch_index
                        .map(|index| cs.get_epoch_data(index))
                        .transpose()
                        .map_err(|err| {
                            ConsensusPoSError::ChainstateError(
                                consensus::ChainstateError::FailedToObtainEpochData(
                                    block_height,
                                    err.to_string(),
                                ),
                            )
                        })?
                        .flatten()
                        .map_or(PoSRandomness::at_genesis(&chain_config), |epoch_data| {
                            *epoch_data.randomness()
                        });

                    let (consensus_data, block_reward) = generate_pos_consensus_data_and_reward(
                        &chain_config,
                        &prev_block_index,
                        input_data.clone(),
                        pos_status,
                        sealed_epoch_randomness,
                        block_timestamp,
                        block_height,
                        Self::ancestor_getter(cs),
                    )?;

                    let finalize_block_data = generate_finalize_block_data_pos(
                        &chain_config,
                        cs,
                        block_height,
                        sealed_epoch_randomness,
                        input_data,
                    )?;

                    Ok((consensus_data, block_reward, finalize_block_data))
                }
            })
            .await?
            .map_err(BlockProductionError::FailedConsensusInitialization)?;

        Ok(consensus_data)
    }

    async fn pull_consensus_data_pow(
        &self,
        input_data: PoWGenerateBlockInputData,
        pow_status: PoWStatus,
        prev_block_index: &GenBlockIndex,
        block_timestamp: BlockTimestamp,
    ) -> Result<(PoWData, BlockReward), BlockProductionError> {
        let consensus_data = self
            .chainstate_handle
            .call({
                let prev_block_index = prev_block_index.clone();
                let chain_config = Arc::clone(&self.chain_config);

                move |cs| {
                    let block_height = prev_block_index.block_height().next_height();
                    let (consensus_data, block_reward) = generate_pow_consensus_data_and_reward(
                        &chain_config,
                        &prev_block_index,
                        block_timestamp,
                        &pow_status,
                        Self::ancestor_getter(cs),
                        input_data.clone(),
                        block_height,
                    )
                    .map_err(ConsensusCreationError::MiningError)?;

                    Ok((consensus_data, block_reward))
                }
            })
            .await?
            .map_err(BlockProductionError::FailedConsensusInitialization)?;

        Ok(consensus_data)
    }

    /// The function that creates a new block.
    ///
    /// Returns the block and a oneshot receiver that will be notified when
    /// the internal job is finished. Generally this can be used to ensure
    /// that the block production process has ended and that there's no
    /// remnants in the job manager.
    pub async fn produce_block(
        &self,
        input_data: GenerateBlockInputData,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<(Block, oneshot::Receiver<usize>), BlockProductionError> {
        self.produce_block_with_custom_id(
            input_data,
            transactions,
            transaction_ids,
            packing_strategy,
            None,
        )
        .await
    }

    async fn ensure_can_produce_block(&self) -> Result<(), BlockProductionError> {
        if !self.blockprod_config.skip_ibd_check {
            let is_initial_block_download =
                self.chainstate_handle.call(|cs| cs.is_initial_block_download()).await?;

            if is_initial_block_download {
                return Err(BlockProductionError::ChainstateWaitForSync);
            }
        }

        let current_peer_count = self
            .p2p_handle
            .call_async_mut(move |p2p| p2p.get_peer_count())
            .await?
            .map_err(|_| BlockProductionError::PeerCountRetrievalError)?;

        if current_peer_count < self.blockprod_config.min_peers_to_produce_blocks {
            return Err(BlockProductionError::PeerCountBelowRequiredThreshold(
                current_peer_count,
                self.blockprod_config.min_peers_to_produce_blocks,
            ));
        }

        Ok(())
    }

    async fn produce_block_with_custom_id(
        &self,
        input_data: GenerateBlockInputData,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
        custom_id_maybe: Option<Vec<u8>>,
    ) -> Result<(Block, oneshot::Receiver<usize>), BlockProductionError> {
        self.ensure_can_produce_block().await?;

        let custom_id = custom_id_maybe.map_or_else(
            || CustomId::new_from_input_data(&input_data),
            CustomId::new_from_value,
        );

        let (helper, _job_stopper_destructor) = Helper::new(
            custom_id,
            &*self.job_manager_handle,
            &self.chainstate_handle,
            &self.chain_config,
            &self.time_getter,
        )
        .await?;

        let required_consensus = helper.required_consensus_at_next_height(&self.chain_config);

        match (required_consensus, input_data) {
            (RequiredConsensus::PoS(pos_status), GenerateBlockInputData::PoS(pos_input_data)) => {
                self.produce_block_pos(
                    helper,
                    pos_status,
                    *pos_input_data,
                    transactions,
                    transaction_ids,
                    packing_strategy,
                )
                .await
            }
            (RequiredConsensus::PoS(_), GenerateBlockInputData::PoW(_)) => Err(
                ConsensusCreationError::StakingError(ConsensusPoSError::PoWInputDataProvided),
            )?,
            (RequiredConsensus::PoS(_), GenerateBlockInputData::None) => Err(
                ConsensusCreationError::StakingError(ConsensusPoSError::NoInputDataProvided),
            )?,
            (RequiredConsensus::PoW(pow_status), GenerateBlockInputData::PoW(pow_input_data)) => {
                self.produce_block_pow(
                    helper,
                    pow_status,
                    *pow_input_data,
                    transactions,
                    transaction_ids,
                    packing_strategy,
                )
                .await
            }
            (RequiredConsensus::PoW(_), GenerateBlockInputData::PoS(_)) => Err(
                ConsensusCreationError::MiningError(ConsensusPoWError::PoSInputDataProvided),
            )?,
            (RequiredConsensus::PoW(_), GenerateBlockInputData::None) => Err(
                ConsensusCreationError::MiningError(ConsensusPoWError::NoInputDataProvided),
            )?,
            (RequiredConsensus::IgnoreConsensus, GenerateBlockInputData::None) => {
                self.produce_block_ignore_consensus(
                    helper,
                    transactions,
                    transaction_ids,
                    packing_strategy,
                )
                .await
            }
            (RequiredConsensus::IgnoreConsensus, GenerateBlockInputData::PoS(_)) => {
                Err(ConsensusCreationError::PoSInputDataProvidedWhenIgnoringConsensus)?
            }
            (RequiredConsensus::IgnoreConsensus, GenerateBlockInputData::PoW(_)) => {
                Err(ConsensusCreationError::PoWInputDataProvidedWhenIgnoringConsensus)?
            }
        }
    }

    async fn produce_block_pos(
        &self,
        helper: Helper,
        pos_status: PoSStatus,
        input_data: PoSGenerateBlockInputData,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<(Block, oneshot::Receiver<usize>), BlockProductionError> {
        // Unlike Proof of Work, which can vary any header field when
        // searching for a valid block, Proof of Stake can only vary
        // the header timestamp. Its search space starts at the
        // previous block's timestamp + 1 second, and ends at the
        // current timestamp + some distance in time defined by the
        // blockchain.
        let starting_timestamp = helper.starting_timestamp();
        let max_timestamp = helper.max_timestamp();

        // Note/TODO: the "vrf_data" part of consensus_data is useless here, because it'll be unconditionally
        // overwritten below. Perhaps we could introduce an intermediate "PartialPoSData" struct that wouldn't
        // contain the vrf data, so that it could be produced by pull_consensus_data_pos instead.
        let (consensus_data, block_reward, finalize_block_data) = self
            .pull_consensus_data_pos(
                input_data,
                pos_status.clone(),
                helper.tip_block_index(),
                starting_timestamp,
            )
            .await?;

        log::debug!(
            "Searching for a valid block ({}..={}), pool_id: {}",
            starting_timestamp,
            max_timestamp,
            Address::new(&self.chain_config, *consensus_data.stake_pool_id())
                .expect("Pool id to address cannot fail")
        );

        let search_start_time = std::time::Instant::now();

        let timestamp_search_result = find_timestamp_for_staking(
            &self.chain_config,
            pos_status.get_chain_config(),
            &consensus_data.target().map_err(ConsensusCreationError::StakingError)?,
            starting_timestamp,
            max_timestamp,
            &finalize_block_data,
        )
        .map_err(ConsensusCreationError::StakingError)?;

        log::debug!("Searching took {:?}", search_start_time.elapsed());

        let (last_used_timestamp, result) = if let Some((timestamp, vrf_data)) =
            timestamp_search_result
        {
            log::info!(
                "Valid block found, timestamp: {}, pool_id: {}",
                timestamp,
                consensus_data.stake_pool_id()
            );

            let mut consensus_data = consensus_data;
            consensus_data.update_vrf_data(vrf_data);

            let tip_block_id = helper.tip_block_index().block_id();

            let collected_transactions = helper
                .collect_transactions(
                    &self.mempool_handle,
                    &self.chain_config,
                    transactions,
                    transaction_ids,
                    packing_strategy,
                )
                .await?;

            let block_body = BlockBody::new(block_reward, collected_transactions);

            let merkle_proxy =
                block_body.merkle_tree_proxy().map_err(BlockCreationError::MerkleTreeError)?;

            let block_header = BlockHeader::new(
                tip_block_id,
                merkle_proxy.merkle_tree().root(),
                merkle_proxy.witness_merkle_tree().root(),
                timestamp,
                ConsensusData::PoS(Box::new(consensus_data)),
            );

            let signed_block_header = finalize_block_data
                .stake_private_key()
                .sign_message(&block_header.encode())
                .map_err(|_| {
                    ConsensusCreationError::StakingError(ConsensusPoSError::FailedToSignBlockHeader)
                })
                .map(BlockHeaderSignatureData::new)
                .map(BlockHeaderSignature::HeaderSignature)
                .map(|signed_data| block_header.with_signature(signed_data))?;

            let block = Block::new_from_header(signed_block_header, block_body)?;
            (timestamp, Ok(block))
        } else {
            // FIXME FailedConsensusInitialization?
            (
                max_timestamp,
                Err(BlockProductionError::FailedConsensusInitialization(
                    ConsensusCreationError::StakingFailed,
                )),
            )
        };

        self.update_last_used_block_timestamp(
            helper.job_custom_id().clone(),
            last_used_timestamp,
        )
        .await?;

        result.map(|block| helper.finish(block))
    }

    async fn produce_block_pow(
        &self,
        mut helper: Helper,
        pow_status: PoWStatus,
        input_data: PoWGenerateBlockInputData,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<(Block, oneshot::Receiver<usize>), BlockProductionError> {
        let block_timestamp = helper.starting_timestamp();
        let tip_block_id = helper.tip_block_index().block_id();

        let (consensus_data, block_reward) = self
            .pull_consensus_data_pow(
                input_data,
                pow_status,
                helper.tip_block_index(),
                block_timestamp,
            )
            .await?;

        let collected_transactions = helper
            .collect_transactions(
                &self.mempool_handle,
                &self.chain_config,
                transactions,
                transaction_ids,
                packing_strategy,
            )
            .await?;

        let block_body = BlockBody::new(block_reward, collected_transactions);

        // Note: job manager is subscribed to chainstate events; when the tip changes, it will
        // cancel all jobs whose job key refers to a different (old) tip.
        let handle = helper.spawn_block_solver(&self.mining_thread_pool, {
            let merkle_proxy =
                block_body.merkle_tree_proxy().map_err(BlockCreationError::MerkleTreeError)?;

            let bits = consensus_data.bits();

            let mut block_header = BlockHeader::new(
                tip_block_id,
                merkle_proxy.merkle_tree().root(),
                merkle_proxy.witness_merkle_tree().root(),
                block_timestamp,
                ConsensusData::PoW(Box::new(consensus_data)),
            );

            move |stop_flag| {
                let mine_result = mine(&mut block_header, u128::MAX, bits, stop_flag)
                    .map_err(ConsensusCreationError::MiningError)?;

                match mine_result {
                    MiningResult::Success => Ok(block_header.with_no_signature()),
                    MiningResult::Failed => Err(ConsensusCreationError::MiningFailed),
                    MiningResult::Stopped => Err(ConsensusCreationError::MiningStopped),
                }
                // FIXME FailedConsensusInitialization?
                .map_err(BlockProductionError::FailedConsensusInitialization)
            }
        });
        let signed_block_header = helper.wait_for_block_solver_result(handle).await?;

        let block = Block::new_from_header(signed_block_header, block_body)?;
        Ok(helper.finish(block))
    }

    async fn produce_block_ignore_consensus(
        &self,
        helper: Helper,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<(Block, oneshot::Receiver<usize>), BlockProductionError> {
        let block_timestamp = helper.starting_timestamp();
        let next_block_height = helper.tip_block_index().block_height().next_height();
        let tip_block_id = helper.tip_block_index().block_id();

        let block_reward = generate_reward_ignore_consensus(&self.chain_config, next_block_height);

        let collected_transactions = helper
            .collect_transactions(
                &self.mempool_handle,
                &self.chain_config,
                transactions,
                transaction_ids,
                packing_strategy,
            )
            .await?;

        let block_body = BlockBody::new(block_reward, collected_transactions);

        let merkle_proxy =
            block_body.merkle_tree_proxy().map_err(BlockCreationError::MerkleTreeError)?;

        let block_header = BlockHeader::new(
            tip_block_id,
            merkle_proxy.merkle_tree().root(),
            merkle_proxy.witness_merkle_tree().root(),
            block_timestamp,
            ConsensusData::None,
        );

        let signed_block_header = block_header.with_no_signature();

        let block = Block::new_from_header(signed_block_header, block_body)?;
        Ok(helper.finish(block))
    }

    pub fn e2e_private_key(&self) -> &ephemeral_e2e::EndToEndPrivateKey {
        &self.e2e_encryption_key
    }
}

async fn collect_transactions(
    mempool_handle: &MempoolHandle,
    chain_config: &ChainConfig,
    current_tip: Id<GenBlock>,
    current_tip_median_time_past: BlockTimestamp,
    transactions: Vec<SignedTransaction>,
    transaction_ids: Vec<Id<Transaction>>,
    packing_strategy: PackingStrategy,
) -> Result<Vec<SignedTransaction>, BlockProductionError> {
    let mut accumulator = Box::new(DefaultTxAccumulator::new(
        chain_config.max_block_size_from_std_scripts(),
        current_tip,
        current_tip_median_time_past,
    ));

    for transaction in transactions.into_iter() {
        let transaction_id = transaction.transaction().get_id();

        accumulator
            .add_tx(transaction, Amount::ZERO.into())
            .map_err(|err| BlockProductionError::FailedToAddTransaction(transaction_id, err))?
    }

    let returned_accumulator = mempool_handle
        .call(move |mempool| mempool.collect_txs(accumulator, transaction_ids, packing_strategy))
        .await??;

    let returned_accumulator =
        returned_accumulator.ok_or(BlockProductionError::RecoverableMempoolError)?;

    Ok(returned_accumulator.transactions().to_vec())
}

fn generate_finalize_block_data_pos(
    chain_config: &ChainConfig,
    chainstate_handle: &dyn ChainstateInterface,
    block_height: BlockHeight,
    sealed_epoch_randomness: PoSRandomness,
    pos_input_data: PoSGenerateBlockInputData,
) -> Result<PoSFinalizeBlockInputData, ConsensusPoSError> {
    let pledge_amount = chainstate_handle
        .get_stake_pool_data(pos_input_data.pool_id())
        .map_err(|err| {
            ConsensusPoSError::ChainstateError(consensus::ChainstateError::StakePoolDataReadError(
                pos_input_data.pool_id(),
                err.to_string(),
            ))
        })?
        .ok_or(ConsensusPoSError::PropertyQueryError(
            PropertyQueryError::StakePoolDataNotFound(pos_input_data.pool_id()),
        ))?
        .staker_balance()
        .map_err(|_| {
            ConsensusPoSError::PropertyQueryError(PropertyQueryError::StakerBalanceOverflow(
                pos_input_data.pool_id(),
            ))
        })?;

    let pool_balance = chainstate_handle
        .get_stake_pool_balance(pos_input_data.pool_id())
        .map_err(|err| {
            ConsensusPoSError::ChainstateError(consensus::ChainstateError::PoolBalanceReadError(
                pos_input_data.pool_id(),
                err.to_string(),
            ))
        })?
        .ok_or(ConsensusPoSError::PropertyQueryError(
            PropertyQueryError::PoolBalanceNotFound(pos_input_data.pool_id()),
        ))?;

    let epoch_index = chain_config.epoch_index_from_height(&block_height);

    Ok(PoSFinalizeBlockInputData::new(
        pos_input_data.stake_private_key().clone(),
        pos_input_data.vrf_private_key().clone(),
        epoch_index,
        sealed_epoch_randomness,
        pledge_amount,
        pool_balance,
    ))
}

#[cfg(test)]
mod tests;
