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
    chain::{signed_transaction::SignedTransaction, tokens::OutputValue},
    primitives::{Amount, Idable},
};

use crate::{error::TxValidationError, get_memory_usage::GetMemoryUsage};

use super::Mempool;

#[async_trait::async_trait]
pub trait TryGetFee {
    async fn try_get_fee(&self, tx: &SignedTransaction) -> Result<Amount, TxValidationError>;
}

#[async_trait::async_trait]
impl<M> TryGetFee for Mempool<M>
where
    M: GetMemoryUsage + Send + Sync,
{
    // TODO this calculation is already done in ChainState, reuse it
    async fn try_get_fee(&self, tx: &SignedTransaction) -> Result<Amount, TxValidationError> {
        eprintln!("try_get_fee");
        let tx_clone = tx.clone();

        // Outputs in this vec are:
        //     Some(Amount) if the outpoint was found in the mainchain
        //     None         if the outpoint wasn't found in the mainchain (maybe it's in the mempool?)
        let chainstate_input_values = self
            .chainstate_handle
            .call(move |this| this.get_inputs_outpoints_values(tx_clone.transaction()))
            .await??;

        let mut input_values = Vec::<Amount>::new();
        for (i, chainstate_input_value) in chainstate_input_values.iter().enumerate() {
            eprintln!("chainstate input value {}: {:?}", i, chainstate_input_value);
            if let Some(value) = chainstate_input_value {
                eprintln!("if");
                input_values.push(*value)
            } else {
                eprintln!("else");
                let value = self.store.get_unconfirmed_outpoint_value(
                    &tx.transaction().get_id(),
                    tx.transaction().inputs().get(i).expect("index").outpoint(),
                )?;
                input_values.push(value);
            }
        }

        let sum_inputs = input_values
            .iter()
            .cloned()
            .sum::<Option<_>>()
            .ok_or(TxValidationError::InputValuesOverflow)?;
        let sum_outputs = tx
            .transaction()
            .outputs()
            .iter()
            .filter_map(|output| match output.value() {
                OutputValue::Coin(coin) => Some(*coin),
                OutputValue::Token(_) => None,
            })
            .sum::<Option<_>>()
            .ok_or(TxValidationError::OutputValuesOverflow)?;
        (sum_inputs - sum_outputs).ok_or(TxValidationError::InputsBelowOutputs)
    }
}
