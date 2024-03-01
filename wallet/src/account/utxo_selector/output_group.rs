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
    chain::{TxInput, TxOutput},
    primitives::Amount,
};

use crate::account::currency_grouper::output_currency_value;

use super::UtxoSelectorError;

/// A group of UTXOs paid to the same output script.
/// This helps reduce privacy leaks resulting from address reuse.
#[derive(Clone)]
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
    pub weight: u32,
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
        weight: u32,
    ) -> Result<Self, UtxoSelectorError> {
        let (_, value) = output_currency_value(&output.1)?;

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
