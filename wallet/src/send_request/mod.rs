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

use common::chain::signature::inputsig::InputWitness;
use common::chain::signature::sighash::sighashtype::SigHashType;
use common::chain::timelock::OutputTimeLock;
use common::chain::tokens::OutputValue;
use common::chain::{
    Destination, OutPoint, SignedTransaction, Transaction, TransactionCreationError, TxInput,
    TxOutput,
};
use utxo::Utxo;

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

impl SendRequest {
    /// Make a `SendRequest` to send to a `Destination` a specific amount
    pub fn transfer_to_destination(amount: OutputValue, destination: Destination) -> Self {
        Self::from_outputs(vec![TxOutput::Transfer(amount, destination)])
    }

    /// Make a `SendRequest` to send to a `Destination` a specific amount that is locked
    pub fn transfer_to_destination_locked(
        amount: OutputValue,
        destination: Destination,
        lock_time: OutputTimeLock,
    ) -> Self {
        Self::from_outputs(vec![TxOutput::LockThenTransfer(
            amount,
            destination,
            lock_time,
        )])
    }

    pub fn from_outputs(outputs: Vec<TxOutput>) -> Self {
        Self {
            flags: 0,
            utxos: Vec::new(),
            inputs: Vec::new(),
            outputs,
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

    pub fn get_sighash_types(&self) -> Vec<SigHashType> {
        // TODO: use customized sig hashes
        let sighash_all = SigHashType::try_from(SigHashType::ALL).expect("Should not fail");
        (0..self.inputs.len()).map(|_| sighash_all).collect()
    }
}
