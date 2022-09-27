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

use super::{signature::inputsig::InputWitness, Transaction};
use crate::{
    chain::TransactionCreationError,
    primitives::{
        id::{self, Idable, WithId},
        Id,
    },
};
use serialization::{Decode, Encode};
use utils::ensure;

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct SignedTransaction {
    transaction: Transaction,
    signatures: Vec<InputWitness>,
}

impl SignedTransaction {
    pub fn new(
        transaction: Transaction,
        signatures: Vec<InputWitness>,
    ) -> Result<Self, TransactionCreationError> {
        ensure!(
            signatures.len() == transaction.inputs().len(),
            TransactionCreationError::InvalidWitnessCount
        );
        Ok(Self {
            transaction,
            signatures,
        })
    }

    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    pub fn signatures(&self) -> &[InputWitness] {
        self.signatures.as_ref()
    }

    /// provides the hash of a transaction including the witness (malleable)
    pub fn serialized_hash(&self) -> Id<Transaction> {
        Id::new(id::hash_encoded(self))
    }
}

impl Idable for SignedTransaction {
    type Tag = Transaction;

    fn get_id(&self) -> Id<Self::Tag> {
        match &self.transaction {
            Transaction::V1(tx) => tx.get_id(),
        }
    }
}

impl PartialEq for WithId<SignedTransaction> {
    fn eq(&self, other: &Self) -> bool {
        WithId::get(self) == WithId::get(other)
    }
}

impl Eq for WithId<SignedTransaction> {}

// TODO(PR): enforce that inputs size is equal to signatures size when decoding

// TODO(PR): add a check in check_transactions and ensure that all signed transactions have sizes equal in witness and inputs
// TODO(PR): add tests to check that inputs and witnesses have the same size

// TODO(PR) make the SignedTransaction serialization ignore the size of the witness vec and just use the size of the inputs
// NOTE: there might be difficulties there as Encode cannot fail. It may lead to accepting a panic there
