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

use common::{chain::SignedTransaction, primitives::Idable};

use crate::{error::TxValidationError, get_memory_usage::GetMemoryUsage};

use super::{fee::Fee, Mempool};

#[async_trait::async_trait]
pub trait TryGetFee {
    async fn try_get_fee(&self, tx: &SignedTransaction) -> Result<Fee, TxValidationError>;
}

#[async_trait::async_trait]
impl<M> TryGetFee for Mempool<M>
where
    M: GetMemoryUsage + Send + Sync,
{
    // TODO this calculation is already done in ChainState, reuse it
    async fn try_get_fee(&self, tx: &SignedTransaction) -> Result<Fee, TxValidationError> {
        let inputs = tx.inputs().to_owned();
        let outputs = tx.outputs().to_owned();

        // Outputs in this vec are:
        //     Some(Amount) if the outpoint was found in the mainchain
        //     None         if the outpoint is token or wasn't found in the mainchain (maybe it's in the mempool?)
        let chainstate_input_values = self
            .chainstate_handle
            .call(move |this| this.get_inputs_outpoints_coin_amount(&inputs))
            .await??;

        let input_values = chainstate_input_values
            .iter()
            .enumerate()
            .map(|(i, chainstate_input_value)| {
                if let Some(value) = chainstate_input_value {
                    Ok(*value)
                } else {
                    self.store.get_unconfirmed_outpoint_value(
                        &tx.transaction().get_id(),
                        tx.transaction().inputs().get(i).expect("index").outpoint(),
                    )
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        let sum_inputs = input_values
            .iter()
            .cloned()
            .sum::<Option<_>>()
            .ok_or(TxValidationError::InputValuesOverflow)?;

        let chainstate_output_values = self
            .chainstate_handle
            .call(move |this| this.get_outputs_coin_amount(&outputs))
            .await??;

        let sum_outputs = chainstate_output_values
            .into_iter()
            .flatten()
            .sum::<Option<_>>()
            .ok_or(TxValidationError::OutputValuesOverflow)?;

        let fee = (sum_inputs - sum_outputs).map(|f| f.into());
        fee.ok_or(TxValidationError::InputsBelowOutputs)
    }
}
