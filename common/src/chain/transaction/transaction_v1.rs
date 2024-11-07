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

pub use crate::chain::transaction::input::*;
pub use crate::chain::transaction::output::*;
pub use crate::chain::transaction::TransactionCreationError;
use crate::primitives::H256;
use crate::primitives::{id, Id, Idable, VersionTag};
use serialization::{Decode, Encode, Tagged};

use super::Transaction;

#[derive(
    Debug, Clone, PartialEq, Eq, Encode, Decode, Tagged, serde::Serialize, serde::Deserialize,
)]
pub struct TransactionV1 {
    version: VersionTag<1>,
    #[codec(compact)]
    flags: u128,
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
}

impl TransactionV1 {
    pub fn new(
        flags: u128,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
    ) -> Result<Self, TransactionCreationError> {
        let tx = TransactionV1 {
            version: VersionTag::default(),
            flags,
            inputs,
            outputs,
        };
        Ok(tx)
    }

    pub fn is_replaceable(&self) -> bool {
        (self.flags & 1) != 0
    }

    pub fn flags(&self) -> u128 {
        self.flags
    }

    pub fn inputs(&self) -> &[TxInput] {
        &self.inputs
    }

    pub fn outputs(&self) -> &[TxOutput] {
        &self.outputs
    }

    pub fn serialized_hash(&self) -> H256 {
        id::hash_encoded(self)
    }
}

impl Idable for TransactionV1 {
    type Tag = Transaction;
    fn get_id(&self) -> Id<Transaction> {
        Id::new(id::hash_encoded(self))
    }
}
