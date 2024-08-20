// Copyright (c) 2021-2022 RBB S.r.l
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

use thiserror::Error;

use serialization::{DirectDecode, DirectEncode};
use typename::TypeName;

use crate::primitives::{id::WithId, Id, Idable, H256};
use crate::text_summary::TextSummary;

pub mod input;
pub use input::*;

pub mod account_outpoint;
pub use account_outpoint::*;

pub mod account_nonce;
pub use account_nonce::*;

pub mod utxo_outpoint;
pub use utxo_outpoint::*;

pub mod signed_transaction;

pub mod signed_transaction_intent;
pub use signed_transaction_intent::*;

pub mod output;
pub use output::*;

pub mod signature;

mod printout;

use self::signature::inputsig::InputWitness;
use self::signed_transaction::SignedTransaction;

mod transaction_v1;
use transaction_v1::TransactionV1;

use super::ChainConfig;

/// In case multiple types of transactions are developed, the size of that transaction can be described here along with its type
pub enum TransactionSize {
    ScriptedTransaction(usize),
    SmartContractTransaction(usize),
}

#[derive(Debug, Clone, PartialEq, Eq, DirectEncode, DirectDecode, TypeName, serde::Serialize)]
pub enum Transaction {
    V1(TransactionV1),
}

impl signature::Signable for Transaction {
    fn inputs(&self) -> Option<&[TxInput]> {
        Some(self.inputs())
    }

    fn outputs(&self) -> Option<&[TxOutput]> {
        Some(self.outputs())
    }

    fn version_byte(&self) -> Option<u8> {
        Some(self.version_byte())
    }

    fn flags(&self) -> Option<u128> {
        Some(self.flags())
    }
}

impl Idable for Transaction {
    type Tag = Transaction;
    fn get_id(&self) -> Id<Transaction> {
        match &self {
            Transaction::V1(tx) => tx.get_id(),
        }
    }
}

impl PartialEq for WithId<Transaction> {
    fn eq(&self, other: &Self) -> bool {
        WithId::get(self) == WithId::get(other)
    }
}

impl Eq for WithId<Transaction> {}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum TransactionCreationError {
    #[error("The number of signatures does not match the number of inputs")]
    InvalidWitnessCount,
}

impl Transaction {
    pub fn new(
        flags: u128,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
    ) -> Result<Self, TransactionCreationError> {
        let tx = Transaction::V1(TransactionV1::new(flags, inputs, outputs)?);
        Ok(tx)
    }

    pub fn version_byte(&self) -> u8 {
        match &self {
            Transaction::V1(tx) => serialization::tagged::tag_of(&tx),
        }
    }

    pub fn is_replaceable(&self) -> bool {
        match &self {
            Transaction::V1(tx) => tx.is_replaceable(),
        }
    }

    pub fn flags(&self) -> u128 {
        match &self {
            Transaction::V1(tx) => tx.flags(),
        }
    }

    pub fn inputs(&self) -> &[TxInput] {
        match &self {
            Transaction::V1(tx) => tx.inputs(),
        }
    }

    pub fn outputs(&self) -> &[TxOutput] {
        match &self {
            Transaction::V1(tx) => tx.outputs(),
        }
    }

    /// provides the hash of a transaction including the witness (malleable)
    pub fn serialized_hash(&self) -> H256 {
        match &self {
            Transaction::V1(tx) => tx.serialized_hash(),
        }
    }

    pub fn has_smart_contracts(&self) -> bool {
        false
    }

    pub fn with_signatures(
        self,
        witnesses: Vec<InputWitness>,
    ) -> Result<SignedTransaction, TransactionCreationError> {
        if witnesses.len() != self.inputs().len() {
            return Err(TransactionCreationError::InvalidWitnessCount);
        }
        SignedTransaction::new(self, witnesses)
    }
}

impl TextSummary for Transaction {
    fn text_summary(&self, chain_config: &ChainConfig) -> String {
        printout::transaction_summary(self, chain_config)
    }
}

impl serde::Serialize for Id<Transaction> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.serde_serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for Id<Transaction> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::serde_deserialize(d)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::Rng;
    use serialization::{Decode, DecodeAll, Encode};

    #[derive(Encode, Decode, Debug, PartialEq, Eq)]
    struct TestCompactU128 {
        #[codec(compact)]
        value: u128,
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn version_byte() {
        let mut rng = randomness::make_pseudo_rng();
        let flags = rng.gen::<u128>();

        let flags_compact = TestCompactU128 { value: flags };

        let tx = Transaction::new(flags, vec![], vec![]).expect("Failed to create test tx");
        let encoded_tx = tx.encode();
        assert_eq!(tx.version_byte(), *encoded_tx.first().unwrap());

        // let's ensure that flags comes right after that
        assert_eq!(
            TestCompactU128::decode_all(&mut &encoded_tx[1..flags_compact.encoded_size() + 1])
                .unwrap(),
            flags_compact
        );
    }
}
