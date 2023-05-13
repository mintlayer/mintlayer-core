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

    inputs: Vec<TxInput>,

    outputs: Vec<TxOutput>,

    lock_time: u32,

    /// The UTXOs for each input, this can be empty
    utxos: Vec<Utxo>,

    /// An optional witness for each transaction. If present the number should be the same as the
    /// transaction's inputs
    witnesses: Option<Vec<InputWitness>>,

    /// If true the wallet will attempt to sign the inputs of the transaction
    sign_transaction: bool,

    // This tracks whether this send request has been completed
    is_complete: bool,
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
            inputs: Vec::new(),
            outputs,
            lock_time: 0,
            utxos: Vec::new(),
            witnesses: None,
            sign_transaction: true,
            is_complete: false,
        }
    }

    pub fn from_transaction(transaction: Transaction) -> Self {
        Self {
            flags: transaction.flags(),
            inputs: transaction.inputs().to_vec(),
            outputs: transaction.outputs().to_vec(),
            lock_time: transaction.lock_time(),
            utxos: Vec::new(),
            witnesses: None,
            sign_transaction: true,
            is_complete: false,
        }
    }

    pub fn get_transaction(&self) -> Result<Transaction, TransactionCreationError> {
        Transaction::new(
            self.flags,
            self.inputs.clone(),
            self.outputs.clone(),
            self.lock_time,
        )
    }

    pub fn get_signed_transaction(&self) -> Result<SignedTransaction, TransactionCreationError> {
        if let Some(w) = &self.witnesses {
            SignedTransaction::new(self.get_transaction()?, w.clone())
        } else {
            Err(TransactionCreationError::InvalidWitnessCount)
        }
    }

    pub fn utxos(&self) -> &Vec<Utxo> {
        &self.utxos
    }

    pub fn sign_transaction(&self) -> bool {
        self.sign_transaction
    }

    pub fn is_complete(&self) -> bool {
        self.is_complete
    }

    pub fn complete(&mut self) {
        self.is_complete = true;
    }

    // pub fn set_connected_tx_outputs(&mut self, utxos: Vec<TxOutput>) {
    //     self.utxos = utxos;
    // }

    // pub fn connected_tx_outputs(&self) -> &Vec<TxOutput> {
    //     &self.utxos
    // }

    pub fn set_witnesses(
        &mut self,
        witnesses: Vec<InputWitness>,
    ) -> Result<(), TransactionCreationError> {
        // SignedTransaction::check_tx_sigs(&self.transaction, &witnesses)?;
        self.witnesses = Some(witnesses);
        Ok(())
    }

    pub fn select_utxos(
        &mut self,
        utxos: BTreeMap<OutPoint, Utxo>,
    ) -> Result<(), TransactionCreationError> {
        for (outpoint, utxo) in utxos.into_iter() {
            self.inputs.push(TxInput::new(outpoint.tx_id(), outpoint.output_index()));
            self.utxos.push(utxo);
        }
        Ok(())
    }

    pub fn get_sighash_types(&self) -> Vec<SigHashType> {
        // TODO use customized sig hashes
        let sighash_all = SigHashType::try_from(SigHashType::ALL).expect("Should not fail");
        (0..self.inputs.len()).map(|_| sighash_all).collect()
    }

    pub fn outputs(&self) -> &[TxOutput] {
        &self.outputs
    }
}
