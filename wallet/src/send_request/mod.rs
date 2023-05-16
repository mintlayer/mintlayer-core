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

use std::collections::BTreeMap;

use common::address::pubkeyhash::PublicKeyHash;
use common::address::Address;
use common::chain::signature::inputsig::InputWitness;
use common::chain::tokens::OutputValue;
use common::chain::{
    Destination, OutPoint, SignedTransaction, Transaction, TransactionCreationError, TxInput,
    TxOutput,
};
use common::primitives::Amount;
use utxo::Utxo;

use crate::{WalletError, WalletResult};

/// The `SendRequest` struct provides the necessary information to the wallet on the precise method
/// of sending funds to a designated destination. In order to facilitate the creation of
#[derive(Debug, Clone)]
pub struct SendRequest {
    flags: u32,

    /// The UTXOs for each input, this can be empty
    utxos: Vec<TxOutput>,

    inputs: Vec<TxInput>,

    outputs: Vec<TxOutput>,

    lock_time: u32,
}

pub fn address_output(address: Address, amount: Amount) -> WalletResult<TxOutput> {
    let pub_key_hash = PublicKeyHash::try_from(&address)
        .map_err(|e| WalletError::InvalidAddress(address.get().to_owned(), e))?;

    let destination = Destination::Address(pub_key_hash);

    Ok(TxOutput::Transfer(OutputValue::Coin(amount), destination))
}

impl SendRequest {
    pub fn new() -> Self {
        Self {
            flags: 0,
            utxos: Vec::new(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
        }
    }

    pub fn from_transaction(transaction: Transaction, utxos: Vec<TxOutput>) -> Self {
        Self {
            flags: transaction.flags(),
            utxos,
            inputs: transaction.inputs().to_vec(),
            outputs: transaction.outputs().to_vec(),
            lock_time: transaction.lock_time(),
        }
    }

    pub fn with_output(mut self, output: TxOutput) -> Self {
        self.outputs.push(output);
        self
    }

    pub fn inputs(&self) -> &[TxInput] {
        &self.inputs
    }

    pub fn outputs(&self) -> &[TxOutput] {
        &self.outputs
    }

    pub fn utxos(&self) -> &[TxOutput] {
        &self.utxos
    }

    pub fn fill_inputs(
        &mut self,
        utxos: BTreeMap<OutPoint, Utxo>,
    ) -> Result<(), TransactionCreationError> {
        for (outpoint, utxo) in utxos.into_iter() {
            self.inputs.push(TxInput::new(outpoint.tx_id(), outpoint.output_index()));
            self.utxos.push(utxo.take_output());
        }
        Ok(())
    }

    pub fn get_transaction(&self) -> Result<Transaction, TransactionCreationError> {
        Transaction::new(
            self.flags,
            self.inputs.clone(),
            self.outputs.clone(),
            self.lock_time,
        )
    }

    pub fn get_signed_transaction(
        &self,
        witnesses: Vec<InputWitness>,
    ) -> Result<SignedTransaction, TransactionCreationError> {
        SignedTransaction::new(self.get_transaction()?, witnesses)
    }
}
