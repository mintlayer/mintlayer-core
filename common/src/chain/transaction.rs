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
use parity_scale_codec::{Decode, Encode};

use crate::chain::transaction::transaction_v1::TransactionV1;

pub mod input;
pub use input::*;

pub mod output;
pub use output::*;

pub mod transaction_index;
pub use transaction_index::*;

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use parity_scale_codec::DecodeAll;

    #[test]
    fn tx_id_collision() {
        let encoded = {
            let mut bytes = [0u8; 36];
            // Compact amount
            bytes[0] = 10 << 2;
            // Destination is an address (enum discriminant)
            bytes[1] = 0;
            // Compact length of address
            bytes[2] = 33 << 2;
            // encoded object
            bytes
        };

        let output = TxOutput::decode(&mut &encoded[..]).expect("decoding output");
        let pt = OutPoint::decode_all(&encoded).expect("decoding outpoint");
        let input = TxInput::new(pt.get_tx_id(), pt.get_output_index(), vec![]);

        let tx0 = Transaction::new(0x00, vec![], vec![output], 0x00).expect("tx0 bad");
        let tx1 = Transaction::new(0x00, vec![input], vec![], 0x00).expect("tx1 bad");
        assert_ne!(tx0, tx1);

        assert_ne!(
            tx0.get_id(),
            tx1.get_id(),
            "Different transactions with the same ID!"
        );
    }
}
