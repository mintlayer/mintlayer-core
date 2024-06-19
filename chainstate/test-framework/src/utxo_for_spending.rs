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

use common::{
    chain::{
        output_value::OutputValue, Destination, OutPointSourceId, SignedTransaction, TxOutput,
        UtxoOutPoint,
    },
    primitives::{Amount, Idable},
};
use randomness::{CryptoRng, Rng};

use crate::{empty_witness, TransactionBuilder};

/// A struct that tracks a utxo and amount available for spending.
#[derive(Clone)]
pub struct UtxoForSpending {
    outpoint: UtxoOutPoint,
    amount_available: Amount,
}

impl UtxoForSpending {
    pub fn new(outpoint: UtxoOutPoint, amount_available: Amount) -> Self {
        Self {
            outpoint,
            amount_available,
        }
    }

    pub fn outpoint(&self) -> &UtxoOutPoint {
        &self.outpoint
    }

    pub fn amount_available(&self) -> Amount {
        self.amount_available
    }

    /// Given a `TransactionBuilder`, add an input and an output to it that spend the specify amount
    /// and transfer the rest to a new outpoint.
    pub fn add_input_and_build_tx(
        &mut self,
        tx_builder: TransactionBuilder,
        amount_to_spend: Amount,
        fee: Amount,
        rng: &mut (impl Rng + CryptoRng),
    ) -> SignedTransaction {
        let change = (self.amount_available - amount_to_spend).unwrap();
        let change = (change - fee).unwrap();
        let change_output_idx = tx_builder.outputs().len();
        let tx = tx_builder
            .add_input(self.outpoint.clone().into(), empty_witness(rng))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(change),
                Destination::AnyoneCanSpend,
            ))
            .build();

        let tx_id = tx.transaction().get_id();

        let change_outpoint = UtxoOutPoint::new(
            OutPointSourceId::Transaction(tx_id),
            change_output_idx as u32,
        );

        self.outpoint = change_outpoint;
        self.amount_available = change;

        tx
    }
}
