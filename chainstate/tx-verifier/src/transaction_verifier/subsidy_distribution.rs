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

use crate::{error::ConnectTransactionError, TransactionSource};

use common::{
    chain::{block::consensus_data::PoSData, Block, ChainConfig},
    primitives::{Amount, BlockHeight, Id},
    Uint256,
};
use pos_accounting::{AccountingBlockRewardUndo, PoSAccountingOperations, PoSAccountingView};

use super::accounting_delta_adapter::PoSAccountingDeltaAdapter;

/// Distribute subsidy among the staker and delegators
pub fn distribute_subsidy<C, P>(
    accounting_adapter: &mut PoSAccountingDeltaAdapter<P>,
    chain_config: &C,
    block_id: Id<Block>,
    block_height: BlockHeight,
    pos_data: &PoSData,
) -> Result<AccountingBlockRewardUndo, ConnectTransactionError>
where
    C: AsRef<ChainConfig>,
    P: PoSAccountingView,
{
    let tx_source = TransactionSource::Chain(block_id);
    let block_subsidy = chain_config.as_ref().block_subsidy_at_height(&block_height);

    let pool_id = *pos_data.stake_pool_id();
    let pool_data = accounting_adapter
        .accounting_delta()
        .get_pool_data(pool_id)?
        .ok_or(ConnectTransactionError::PoolDataNotFound(pool_id))?;

    let increase_balance_undo = accounting_adapter
        .operations(tx_source)
        .increase_pool_balance(pool_id, block_subsidy)?;

    let total_delegators_reward = (block_subsidy - pool_data.cost_per_block())
        .and_then(|v| (v * pool_data.margin_ratio_per_thousand().into()).and_then(|v| v / 1000))
        .ok_or(ConnectTransactionError::StakerRewardCalculationFailed(
            block_id,
        ))?;
    let total_delegators_reward = Uint256::from_amount(total_delegators_reward);

    let delegation_undos = accounting_adapter
        .accounting_delta()
        .get_pool_delegations_shares(pool_id)?
        .map(|delegation_shares| {
            let total_delegators_balance =
                delegation_shares.values().try_fold(Amount::ZERO, |acc, v| {
                    (acc + *v).ok_or(ConnectTransactionError::DelegatorsRewardSumFailed(block_id))
                })?;
            let total_delegators_balance = Uint256::from_amount(total_delegators_balance);

            delegation_shares
                .iter()
                .map(|(delegation_id, balance)| {
                    let balance = Uint256::from_amount(*balance);
                    let reward = total_delegators_reward * balance / total_delegators_balance;
                    let reward: u128 = reward.try_into().map_err(|_| {
                        ConnectTransactionError::DelegatorRewardCalculationFailed(block_id)
                    })?;

                    accounting_adapter
                        .operations(tx_source)
                        .delegate_staking(*delegation_id, Amount::from_atoms(reward))
                        .map_err(ConnectTransactionError::PoSAccountingError)
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    let undos = delegation_undos
        .unwrap_or_default()
        .into_iter()
        .chain(vec![increase_balance_undo].into_iter())
        .collect();

    Ok(AccountingBlockRewardUndo::new(undos))
}
