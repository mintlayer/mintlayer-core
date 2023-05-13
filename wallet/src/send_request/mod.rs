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

use common::chain::signature::inputsig::InputWitness;
use common::chain::signature::sighash::sighashtype::SigHashType;
use common::chain::timelock::OutputTimeLock;
use common::chain::tokens::OutputValue;
use common::chain::{
    Destination, SignedTransaction, Transaction, TransactionCreationError, TxOutput,
};

/// The `SendRequest` struct provides the necessary information to the wallet on the precise method
/// of sending funds to a designated destination. In order to facilitate the creation of
#[derive(Debug, Clone)]
pub struct SendRequest {
    /// A transaction outline that is typically incomplete and includes outputs to intended
    /// destinations but no inputs, change address or fees. The wallet will calculate these
    /// missing elements and update the transaction later.
    transaction: Transaction,

    /// The UTXOs for each input, this can be empty
    utxos: Vec<TxOutput>,

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
    pub fn transfer_to_destination(
        amount: OutputValue,
        destination: Destination,
    ) -> Result<Self, TransactionCreationError> {
        Ok(Self::from_transaction(Transaction::new(
            0,
            vec![],
            vec![TxOutput::Transfer(amount, destination)],
            0,
        )?))
    }

    /// Make a `SendRequest` to send to a `Destination` a specific amount that is locked
    pub fn transfer_to_destination_locked(
        amount: OutputValue,
        destination: Destination,
        lock_time: OutputTimeLock,
    ) -> Result<Self, TransactionCreationError> {
        Ok(Self::from_transaction(Transaction::new(
            0,
            vec![],
            vec![TxOutput::LockThenTransfer(amount, destination, lock_time)],
            0,
        )?))
    }

    pub fn from_transaction(transaction: Transaction) -> Self {
        Self {
            transaction,
            utxos: Vec::new(),
            witnesses: None,
            sign_transaction: true,
            is_complete: false,
        }
    }

    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    pub fn set_utxos(&mut self, utxos: Vec<TxOutput>) {
        self.utxos = utxos
    }

    pub fn utxos(&self) -> &[TxOutput] {
        &self.utxos
    }

    pub fn into_transaction(self) -> Transaction {
        self.transaction
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

    pub fn set_connected_tx_outputs(&mut self, utxos: Vec<TxOutput>) {
        self.utxos = utxos;
    }

    pub fn connected_tx_outputs(&self) -> &Vec<TxOutput> {
        &self.utxos
    }

    pub fn signed_transaction(&self) -> Option<SignedTransaction> {
        if let Some(w) = &self.witnesses {
            SignedTransaction::new(self.transaction.clone(), w.clone()).ok()
        } else {
            None
        }
    }

    pub fn set_witnesses(
        &mut self,
        witnesses: Vec<InputWitness>,
    ) -> Result<(), TransactionCreationError> {
        SignedTransaction::check_tx_sigs(&self.transaction, &witnesses)?;
        self.witnesses = Some(witnesses);
        Ok(())
    }

    pub fn get_sighash_types(&self) -> Vec<SigHashType> {
        // TODO use customized sig hashes
        let sighash_all = SigHashType::try_from(SigHashType::ALL).expect("Should not fail");
        (0..self.transaction.inputs().len()).map(|_| sighash_all).collect()
    }
}
