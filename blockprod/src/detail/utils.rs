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

use chainstate::{
    chainstate_interface::ChainstateInterface, BlockIndex, GenBlockIndex, NonZeroPoolBalances,
};
use chainstate_types::{pos_randomness::PoSRandomness, EpochData};
use common::{
    chain::{
        block::{
            consensus_data::PoSData,
            timestamp::{BlockTimestamp, BlockTimestampInternalType},
            BlockHeader, ConsensusData,
        },
        Block, ChainConfig, GenBlock, PoSStatus, PoolId, RequiredConsensus, SignedTransaction,
        Transaction,
    },
    primitives::{Amount, BlockHeight, Id, Idable},
};
use mempool::{
    tx_accumulator::{DefaultTxAccumulator, PackingStrategy, TransactionAccumulator},
    MempoolHandle,
};

use crate::BlockProductionError;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum PoSAccountingError {
    #[error("Staker balance retrieval error: {0}")]
    StakerBalanceRetrievalError(String),
}

pub fn get_pool_balances_at_heights<CS: ChainstateInterface + ?Sized>(
    chainstate: &CS,
    min_height: BlockHeight,
    max_height: BlockHeight,
    pool_id: &PoolId,
) -> Result<impl Iterator<Item = (BlockHeight, NonZeroPoolBalances)>, BlockProductionError> {
    let balances = chainstate
        .get_stake_pool_balances_at_heights(&[*pool_id], min_height, max_height)
        .map_err(|err| {
            BlockProductionError::ChainstateError(consensus::ChainstateError::PoolBalanceReadError(
                *pool_id,
                err.to_string(),
            ))
        })?;

    let pool_id = *pool_id;
    let balances_iter = balances.into_iter().filter_map(move |(height, balances)| {
        balances.get(&pool_id).map(|balance| (height, balance.clone()))
    });

    Ok(balances_iter)
}

#[allow(dead_code)]
pub fn get_pool_balances_at_height<CS: ChainstateInterface + ?Sized>(
    chainstate: &CS,
    height: BlockHeight,
    pool_id: &PoolId,
) -> Result<NonZeroPoolBalances, BlockProductionError> {
    let mut iter = get_pool_balances_at_heights(chainstate, height, height, pool_id)?;

    let (_, balances) = iter
        .find(|(h, _)| *h == height)
        .ok_or(BlockProductionError::PoolBalanceNotFound(*pool_id))?;

    Ok(balances)
}

pub fn get_epoch_data<CS: ChainstateInterface + ?Sized>(
    chainstate: &CS,
    epoch_index: u64,
) -> Result<Option<EpochData>, BlockProductionError> {
    chainstate.get_epoch_data(epoch_index).map_err(|err| {
        BlockProductionError::ChainstateError(consensus::ChainstateError::FailedToObtainEpochData {
            epoch_index,
            error: err.to_string(),
        })
    })
}

pub fn get_sealed_epoch_randomness<CS: ChainstateInterface + ?Sized>(
    chain_config: &ChainConfig,
    chainstate: &CS,
    block_height: BlockHeight,
) -> Result<PoSRandomness, BlockProductionError> {
    let sealed_epoch_index = chain_config.sealed_epoch_index(&block_height);
    get_sealed_epoch_randomness_from_sealed_epoch_index(
        chain_config,
        chainstate,
        sealed_epoch_index,
    )
}

pub fn get_sealed_epoch_randomness_from_sealed_epoch_index<CS: ChainstateInterface + ?Sized>(
    chain_config: &ChainConfig,
    chainstate: &CS,
    sealed_epoch_index: Option<u64>,
) -> Result<PoSRandomness, BlockProductionError> {
    let sealed_epoch_randomness = sealed_epoch_index
        .map(|index| get_epoch_data(chainstate, index))
        .transpose()?
        .flatten()
        .map_or(PoSRandomness::at_genesis(chain_config), |epoch_data| {
            *epoch_data.randomness()
        });
    Ok(sealed_epoch_randomness)
}

pub fn calculate_median_time_past<CS: ChainstateInterface + ?Sized>(
    chainstate: &CS,
    starting_block: &Id<GenBlock>,
) -> Result<BlockTimestamp, BlockProductionError> {
    chainstate.calculate_median_time_past(starting_block).map_err(|err| {
        BlockProductionError::ChainstateError(
            consensus::ChainstateError::FailedToCalculateMedianTimePast(
                *starting_block,
                err.to_string(),
            ),
        )
    })
}

pub fn pos_data_from_header(
    block_header: &BlockHeader,
) -> Result<&'_ PoSData, BlockProductionError> {
    match block_header.consensus_data() {
        ConsensusData::PoS(pos_data) => Ok(pos_data),

        ConsensusData::PoW(_) => Err(BlockProductionError::UnexpectedConsensusTypePoW),
        ConsensusData::None => Err(BlockProductionError::UnexpectedConsensusTypeNone),
    }
}

pub fn pos_status_from_height(
    chain_config: &ChainConfig,
    height: BlockHeight,
) -> Result<PoSStatus, BlockProductionError> {
    match chain_config.consensus_upgrades().consensus_status(height) {
        RequiredConsensus::PoS(pos_status) => Ok(pos_status),

        RequiredConsensus::PoW(_) => Err(BlockProductionError::UnexpectedConsensusTypePoW),
        RequiredConsensus::IgnoreConsensus => {
            Err(BlockProductionError::UnexpectedConsensusTypeNone)
        }
    }
}

pub fn make_ancestor_getter<CS: ChainstateInterface + ?Sized>(
    cs: &CS,
) -> impl Fn(&BlockIndex, BlockHeight) -> Result<GenBlockIndex, consensus::ChainstateError> + '_ {
    |block_index: &BlockIndex, ancestor_height: BlockHeight| {
        cs.get_ancestor(&block_index.clone().into_gen_block_index(), ancestor_height)
            .map_err(|err| {
                consensus::ChainstateError::FailedToObtainAncestor(
                    *block_index.block_id(),
                    ancestor_height,
                    err.to_string(),
                )
            })
    }
}

pub fn get_best_block_index<CS: ChainstateInterface + ?Sized>(
    chainstate: &CS,
) -> Result<GenBlockIndex, BlockProductionError> {
    chainstate.get_best_block_index().map_err(|err| {
        BlockProductionError::ChainstateError(
            consensus::ChainstateError::FailedToObtainBestBlockIndex(err.to_string()),
        )
    })
}

pub fn get_existing_block_index<CS: ChainstateInterface + ?Sized>(
    chainstate: &CS,
    block_id: &Id<Block>,
) -> Result<BlockIndex, BlockProductionError> {
    let block_index = chainstate
        .get_block_index_for_persisted_block(block_id)
        .map_err(|err| {
            BlockProductionError::ChainstateError(
                consensus::ChainstateError::FailedToObtainBlockIndex(
                    (*block_id).into(),
                    err.to_string(),
                ),
            )
        })?
        .ok_or(BlockProductionError::InconsistentDbMissingBlockIndex(
            (*block_id).into(),
        ))?;

    Ok(block_index)
}

pub fn get_existing_gen_block_index<CS: ChainstateInterface + ?Sized>(
    chainstate: &CS,
    block_id: &Id<GenBlock>,
) -> Result<GenBlockIndex, BlockProductionError> {
    let block_index = chainstate
        .get_gen_block_index_for_persisted_block(block_id)
        .map_err(|err| {
            BlockProductionError::ChainstateError(
                consensus::ChainstateError::FailedToObtainBlockIndex(*block_id, err.to_string()),
            )
        })?
        .ok_or(BlockProductionError::InconsistentDbMissingBlockIndex(
            *block_id,
        ))?;

    Ok(block_index)
}

pub fn get_block_id_from_height<CS: ChainstateInterface + ?Sized>(
    chainstate: &CS,
    height: BlockHeight,
) -> Result<Id<GenBlock>, BlockProductionError> {
    let block_id = chainstate
        .get_block_id_from_height(&height)
        .map_err(|err| {
            BlockProductionError::ChainstateError(
                consensus::ChainstateError::FailedToObtainBlockIdFromHeight(
                    height,
                    err.to_string(),
                ),
            )
        })?
        .ok_or(BlockProductionError::NoBlockForHeight(height))?;

    Ok(block_id)
}

pub fn timestamp_add_secs(
    timestamp: BlockTimestamp,
    secs: BlockTimestampInternalType,
) -> Result<BlockTimestamp, BlockProductionError> {
    let timestamp = timestamp
        .add_int_seconds(secs)
        .ok_or(BlockProductionError::TimestampOverflow(timestamp, secs))?;
    Ok(timestamp)
}

/// Collect transactions from the mempool.
/// Ok(None) means that a recoverable error happened (such as that the mempool tip moved).
pub async fn collect_transactions(
    mempool_handle: &MempoolHandle,
    chain_config: &ChainConfig,
    current_tip: Id<GenBlock>,
    current_tip_median_time_past: BlockTimestamp,
    transactions: Vec<SignedTransaction>,
    transaction_ids: Vec<Id<Transaction>>,
    packing_strategy: PackingStrategy,
) -> Result<Option<Vec<SignedTransaction>>, BlockProductionError> {
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

    let transactions = returned_accumulator
        .map(|returned_accumulator| returned_accumulator.transactions().to_vec());

    Ok(transactions)
}
