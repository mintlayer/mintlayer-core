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

use std::hash::Hasher;
use std::primitive;

use crate::primitives::id;
use crate::primitives::Amount;
use crate::primitives::Id;
use crate::primitives::Idable;
use crate::primitives::H256;
use crypto::hash::StreamHasher;
use script::Script;

pub mod transaction_index;
pub use transaction_index::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutPoint {
    pub hash: H256,
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInput {
    pub outpoint: OutPoint,
    pub witness: Vec<Script>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    Address,   // Address type to be added
    PublicKey, // Key type to be added
    ScriptHash(Script),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutput {
    pub value: Amount,
    pub dest: Destination,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionV1 {
    pub flags: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u32,
}

impl TransactionV1 {
    fn is_replaceable(&self) -> bool {
        (self.flags & 1) != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transaction {
    V1(TransactionV1), // TODO: add serialization index attribute
}

impl Idable<TransactionV1> for TransactionV1 {
    fn get_id(&self) -> Id<Self> {
        let mut hash_stream = id::DefaultHashAlgoStream::new();
        // hash_stream.write(self.flags);
        for input in &self.inputs {
            hash_stream.write(input.outpoint.hash);
            // hash_stream.write(input.outpoint.index);
        }
        for _output in &self.outputs {
            // hash_stream.write(output.value);
            // hash_stream.write(output.dest);
        }
        // hash_stream.write(self.lock_time);
        Id::new(&H256::from(hash_stream.finalize().as_slice()))
    }
}

impl Into<Id<Transaction>> for Id<TransactionV1> {
    fn into(self) -> Id<Transaction> {
        Id::new(self.get())
    }
}

impl Idable<Transaction> for Transaction {
    fn get_id(&self) -> Id<Transaction> {
        match &self {
            Transaction::V1(tx) => tx.get_id().into(),
        }
    }
}

impl Transaction {
    pub fn is_replaceable(&self) -> bool {
        match &self {
            Transaction::V1(tx) => tx.is_replaceable(),
        }
    }
}
