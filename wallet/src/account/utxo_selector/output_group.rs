// Copyright (c) 2023 RBB S.r.l
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
    chain::{output_value::OutputValue, tokens::TokenData, TxInput, TxOutput},
    primitives::Amount,
};

use super::UtxoSelectorError;

/// A group of UTXOs paid to the same output script.
/// This helps reduce privacy leaks resulting from address reuse.
#[derive(Clone, Debug)]
pub struct OutputGroup {
    /// The list of UTXOs contained in this output group.
    pub outputs: Vec<(TxInput, TxOutput)>,
    /// the total amount of the outputs in this group
    pub value: Amount,
    /// The fee cost of these UTXOs at the effective feerate.
    /// weight * feerate
    pub fee: Amount,
    /// The fee cost of these UTXOs at the long term feerate.
    /// weight * long_term_feerate
    pub long_term_fee: Amount,
    /// Total weight of the UTXOs in this group.
    /// the size in bytes of the UTXOs
    pub weight: usize,
}

/// Should we pay fee with this currency or not in the case we pay the total fees with another
/// currency. Here Currency refers to either a coin or a token_id.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PayFee {
    PayFeeWithThisCurrency,
    DoNotPayFeeWithThisCurrency,
}

impl OutputGroup {
    pub fn new(
        output: (TxInput, TxOutput),
        fee: Amount,
        long_term_fee: Amount,
        weight: usize,
    ) -> Result<Self, UtxoSelectorError> {
        let output_value = match &output.1 {
            TxOutput::Transfer(v, _)
            | TxOutput::LockThenTransfer(v, _, _)
            | TxOutput::Htlc(v, _) => v.clone(),
            TxOutput::IssueNft(token_id, _, _) => {
                OutputValue::TokenV1(*token_id, Amount::from_atoms(1))
            }
            TxOutput::CreateStakePool(_, _)
            | TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::Burn(_)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::DataDeposit(_)
            | TxOutput::CreateOrder(_) => {
                return Err(UtxoSelectorError::UnsupportedTransactionOutput(Box::new(
                    output.1.clone(),
                )))
            }
        };
        let value = match output_value {
            OutputValue::Coin(output_amount) => output_amount,
            OutputValue::TokenV0(token_data) => {
                let token_data = token_data.as_ref();
                match token_data {
                    TokenData::TokenTransfer(token_transfer) => token_transfer.amount,
                    TokenData::TokenIssuance(token_issuance) => token_issuance.amount_to_issue,
                    TokenData::NftIssuance(_) => Amount::from_atoms(1),
                }
            }
            OutputValue::TokenV1(_, output_amount) => output_amount,
        };

        Ok(Self {
            outputs: vec![output],
            value,
            fee,
            long_term_fee,
            weight,
        })
    }

    pub fn get_effective_value(&self, pay_fees: PayFee) -> Amount {
        match pay_fees {
            PayFee::PayFeeWithThisCurrency => (self.value - self.fee)
                .expect("fee should have been checked to be less than the value"),
            PayFee::DoNotPayFeeWithThisCurrency =>
            // fee will be payed with another currency
            {
                self.value
            }
        }
    }
}
