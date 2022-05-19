// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): S. Afach

use crate::primitives::{Id, Idable};
use serialization::{Decode, Encode};

use crate::chain::transaction::transaction_v1::TransactionV1;

pub mod input;
pub use input::*;

pub mod output;
pub use output::*;

pub mod signature;

pub mod transaction_index;
pub use transaction_index::*;

use self::signature::inputsig::InputWitness;

mod transaction_v1;

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum Transaction {
    #[codec(index = 1)]
    V1(TransactionV1),
}

impl From<Id<TransactionV1>> for Id<Transaction> {
    fn from(id_tx_v1: Id<TransactionV1>) -> Id<Transaction> {
        Id::new(&id_tx_v1.get())
    }
}

impl Idable<Transaction> for Transaction {
    fn get_id(&self) -> Id<Transaction> {
        match &self {
            Transaction::V1(tx) => tx.get_id().into(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum TransactionCreationError {
    Unknown,
}

#[derive(Debug, Clone)]
pub enum TransactionUpdateError {
    Unknown,
}

impl Transaction {
    pub fn new(
        flags: u32,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        lock_time: u32,
    ) -> Result<Self, TransactionCreationError> {
        let tx = Transaction::V1(TransactionV1::new(flags, inputs, outputs, lock_time)?);
        Ok(tx)
    }

    pub fn version_byte(&self) -> u8 {
        let result = match &self {
            Transaction::V1(_) => 1,
        };
        debug_assert_eq!(
            result,
            *self.encode().get(0).expect("Unexpected version byte")
        );
        result
    }

    pub fn is_replaceable(&self) -> bool {
        match &self {
            Transaction::V1(tx) => tx.is_replaceable(),
        }
    }

    pub fn get_flags(&self) -> u32 {
        match &self {
            Transaction::V1(tx) => tx.get_flags(),
        }
    }

    pub fn get_inputs(&self) -> &Vec<TxInput> {
        match &self {
            Transaction::V1(tx) => tx.get_inputs(),
        }
    }

    pub fn get_outputs(&self) -> &Vec<TxOutput> {
        match &self {
            Transaction::V1(tx) => tx.get_outputs(),
        }
    }

    pub fn get_lock_time(&self) -> u32 {
        match &self {
            Transaction::V1(tx) => tx.get_lock_time(),
        }
    }

    /// provides the hash of a transaction including the witness (malleable)
    pub fn get_serialized_hash(&self) -> Id<Transaction> {
        match &self {
            Transaction::V1(tx) => tx.get_serialized_hash(),
        }
    }

    pub fn update_witness(
        &mut self,
        input_index: usize,
        witness: InputWitness,
    ) -> Result<(), TransactionUpdateError> {
        match self {
            Transaction::V1(tx) => tx.update_witness(input_index, witness),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crypto::random::{RngCore, SeedableRng};

    #[test]
    #[allow(clippy::eq_op)]
    fn version_byte() {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let flags = rng.next_u32();
        let lock_time = rng.next_u32();

        let tx =
            Transaction::new(flags, vec![], vec![], lock_time).expect("Failed to create test tx");
        let encoded_tx = tx.encode();
        assert_eq!(tx.version_byte(), *encoded_tx.get(0).unwrap());

        // let's ensure that flags comes right after that
        assert_eq!(u32::decode(&mut &encoded_tx[1..5]).unwrap(), flags);
    }
}
