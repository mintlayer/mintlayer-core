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

use std::collections::BTreeMap;

use chainstate::{
    chainstate_interface::ChainstateInterface, BlockIndex, GenBlockIndex, NonZeroPoolBalances,
};
use chainstate_types::{pos_randomness::PoSRandomness, EpochData};
use common::{
    chain::{
        block::timestamp::{BlockTimestamp, BlockTimestampInternalType},
        ChainConfig, PoolId,
    },
    primitives::{Amount, BlockHeight},
};

use crate::BlockProductionError;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum PoSAccountingError {
    #[error("Staker balance retrieval error: {0}")]
    StakerBalanceRetrievalError(String),
}

pub fn get_pool_staker_balance(
    chainstate: &dyn ChainstateInterface,
    pool_id: &PoolId,
) -> Result<Amount, BlockProductionError> {
    let balance = chainstate
        .get_stake_pool_data(*pool_id)
        .map_err(|err| {
            BlockProductionError::ChainstateError(
                consensus::ChainstateError::StakePoolDataReadError(*pool_id, err.to_string()),
            )
        })?
        .ok_or(BlockProductionError::PoolDataNotFound(*pool_id))?
        .staker_balance()
        .map_err(|err| PoSAccountingError::StakerBalanceRetrievalError(err.to_string()))?;

    Ok(balance)
}

pub fn get_pool_total_balance(
    chainstate: &dyn ChainstateInterface,
    pool_id: &PoolId,
) -> Result<Amount, BlockProductionError> {
    let pool_balance = chainstate
        .get_stake_pool_balance(*pool_id)
        .map_err(|err| {
            BlockProductionError::ChainstateError(consensus::ChainstateError::PoolBalanceReadError(
                *pool_id,
                err.to_string(),
            ))
        })?
        .ok_or(BlockProductionError::PoolBalanceNotFound(*pool_id))?;

    Ok(pool_balance)
}

pub fn get_pool_balances_at_heights(
    chainstate: &dyn ChainstateInterface,
    min_height: BlockHeight,
    max_height: BlockHeight,
    pool_id: &PoolId,
) -> Result<BTreeMap<BlockHeight, NonZeroPoolBalances>, BlockProductionError> {
    let balances = chainstate
        .get_stake_pool_balances_at_heights(&[*pool_id], min_height, max_height)
        .map_err(|err| {
            BlockProductionError::ChainstateError(consensus::ChainstateError::PoolBalanceReadError(
                *pool_id,
                err.to_string(),
            ))
        })?;

    let balances = balances
        .iter()
        .filter_map(|(height, balances)| {
            balances.get(pool_id).map(|balance| (*height, balance.clone()))
        })
        .collect::<BTreeMap<_, _>>();

    Ok(balances)
}

pub fn get_pool_balances_at_height(
    chainstate: &dyn ChainstateInterface,
    height: BlockHeight,
    pool_id: &PoolId,
) -> Result<NonZeroPoolBalances, BlockProductionError> {
    let mut height_map = get_pool_balances_at_heights(chainstate, height, height, pool_id)?;

    let balances = height_map
        .remove(&height)
        .ok_or(BlockProductionError::PoolBalanceNotFound(*pool_id))?;

    Ok(balances)
}

pub fn get_epoch_data(
    chainstate: &dyn ChainstateInterface,
    epoch_index: u64,
) -> Result<Option<EpochData>, BlockProductionError> {
    chainstate.get_epoch_data(epoch_index).map_err(|err| {
        BlockProductionError::ChainstateError(consensus::ChainstateError::FailedToObtainEpochData {
            epoch_index,
            error: err.to_string(),
        })
    })
}

pub fn get_sealed_epoch_randomness(
    chain_config: &ChainConfig,
    chainstate: &dyn ChainstateInterface,
    block_height: BlockHeight,
) -> Result<PoSRandomness, BlockProductionError> {
    let sealed_epoch_index = chain_config.sealed_epoch_index(&block_height);
    get_sealed_epoch_randomness_from_sealed_epoch_index(
        chain_config,
        chainstate,
        sealed_epoch_index,
    )
}

pub fn get_sealed_epoch_randomness_from_sealed_epoch_index(
    chain_config: &ChainConfig,
    chainstate: &dyn ChainstateInterface,
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

pub fn make_ancestor_getter(
    cs: &dyn ChainstateInterface,
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

pub fn get_best_block_index(
    chainstate: &dyn ChainstateInterface,
) -> Result<GenBlockIndex, BlockProductionError> {
    chainstate.get_best_block_index().map_err(|err| {
        BlockProductionError::ChainstateError(
            consensus::ChainstateError::FailedToObtainBestBlockIndex(err.to_string()),
        )
    })
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
