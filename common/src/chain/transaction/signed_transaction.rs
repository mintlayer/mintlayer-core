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

use super::{signature::inputsig::InputWitness, Transaction, TransactionSize, TxOutput};
use crate::{
    chain::{TransactionCreationError, TxInput},
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

    pub fn version_byte(&self) -> u8 {
        self.transaction.version_byte()
    }

    pub fn is_replaceable(&self) -> bool {
        self.transaction.is_replaceable()
    }

    pub fn flags(&self) -> u32 {
        self.transaction.flags()
    }

    pub fn inputs(&self) -> &Vec<TxInput> {
        self.transaction.inputs()
    }

    pub fn outputs(&self) -> &Vec<TxOutput> {
        self.transaction.outputs()
    }

    pub fn lock_time(&self) -> u32 {
        self.transaction.lock_time()
    }

    pub fn has_smart_contracts(&self) -> bool {
        self.transaction.has_smart_contracts()
    }

    pub fn transaction_data_size(&self) -> TransactionSize {
        if self.has_smart_contracts() {
            TransactionSize::SmartContractTransaction(self.encoded_size())
        } else {
            TransactionSize::ScriptedTransaction(self.encoded_size())
        }
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

// TODO enforce that inputs size is equal to signatures size when decoding

// TODO make the SignedTransaction serialization ignore the size of the witness vec and just use the size of the inputs
// NOTE: there might be difficulties there as Encode cannot fail. It may lead to accepting a panic there

#[cfg(test)]
mod tests {
    use super::*;

    use crate::chain::TxInput;
    use crate::primitives::H256;

    #[test]
    fn require_inputs_witnesses_same_size() {
        let hash0 = H256([0x50; 32]);
        let hash1 = H256([0x51; 32]);
        let hash2 = H256([0x52; 32]);

        let ins0: Vec<TxInput> = [TxInput::new(Id::<Transaction>::new(hash0).into(), 5)].to_vec();
        let ins1: Vec<TxInput> = [
            TxInput::new(Id::<Transaction>::new(hash1).into(), 3),
            TxInput::new(Id::<Transaction>::new(hash2).into(), 0),
        ]
        .to_vec();

        let tx = Transaction::new(0x00, vec![], vec![], 0x01).unwrap();
        assert!(SignedTransaction::new(tx.clone(), vec![]).is_ok());
        assert_eq!(
            SignedTransaction::new(tx, vec![InputWitness::NoSignature(None)]),
            Err(TransactionCreationError::InvalidWitnessCount)
        );

        let tx = Transaction::new(0x00, ins0, vec![], 0x00).unwrap();
        assert!(SignedTransaction::new(tx.clone(), vec![InputWitness::NoSignature(None)]).is_ok());
        assert_eq!(
            SignedTransaction::new(tx, vec![]),
            Err(TransactionCreationError::InvalidWitnessCount)
        );

        let tx = Transaction::new(0x00, ins1, vec![], 0x00).unwrap();
        assert!(SignedTransaction::new(
            tx.clone(),
            vec![
                InputWitness::NoSignature(Some(vec![0x01, 0x05, 0x09])),
                InputWitness::NoSignature(Some(vec![0x91, 0x55, 0x19, 0x00])),
            ],
        )
        .is_ok());
        assert_eq!(
            SignedTransaction::new(
                tx.clone(),
                vec![InputWitness::NoSignature(Some(vec![0x01, 0x05, 0x09]))]
            ),
            Err(TransactionCreationError::InvalidWitnessCount)
        );
        assert_eq!(
            SignedTransaction::new(tx, vec![]),
            Err(TransactionCreationError::InvalidWitnessCount)
        );
    }
}
