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

use common::{
    chain::{block::BlockRewardTransactable, ChainConfig, Transaction},
    primitives::{BlockDistance, BlockHeight},
};
use pos_accounting::PoSAccountingView;

use thiserror::Error;

use super::error::ConnectTransactionError;

mod constraints_accumulator;
mod purposes_check;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum IOPolicyError {
    #[error("Attempted to use a invalid input type in block reward")]
    InvalidInputTypeInReward,
    #[error("Attempted to use a invalid output type in block reward")]
    InvalidOutputTypeInReward,
    #[error("Attempted to use a invalid input type in a tx")]
    InvalidInputTypeInTx,
    #[error("Attempted to create multiple stake pools in a single tx")]
    MultiplePoolCreated,
    #[error("Attempted to create multiple delegations in a single tx")]
    MultipleDelegationCreated,
    #[error("Attempted to produce block in a tx")]
    ProduceBlockInTx,
    #[error("Timelock requirement was not satisfied for `{0}`")]
    TimelockRequirementNotSatisfied(BlockDistance),
    #[error("Constraint amount overflow")]
    ConstrainedAmountOverflow,
}

pub fn check_reward_inputs_outputs_policy(
    reward: &BlockRewardTransactable,
    utxo_view: &impl utxo::UtxosView,
) -> Result<(), ConnectTransactionError> {
    purposes_check::check_reward_inputs_outputs_purposes(reward, utxo_view)
}

pub fn check_tx_inputs_outputs_policy(
    tx: &Transaction,
    chain_config: &ChainConfig,
    block_height: BlockHeight,
    pos_accounting_view: &impl PoSAccountingView,
    utxo_view: &impl utxo::UtxosView,
) -> Result<(), ConnectTransactionError> {
    purposes_check::check_tx_inputs_outputs_purposes(tx, utxo_view)?;

    let mut constraints_accumulator = constraints_accumulator::ConstrainedValueAccumulator::new();
    constraints_accumulator.collect_and_verify(
        tx,
        chain_config,
        block_height,
        pos_accounting_view,
        utxo_view,
    )?;

    Ok(())
}

//#[cfg(test)]
//mod tests;
