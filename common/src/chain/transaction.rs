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

use crate::primitives::Amount;
use crate::primitives::Idable;
use crate::primitives::H256;
use script::Script;

pub mod transaction_index;
pub use transaction_index::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutPoint {
    pub hash_output: H256,
    pub index_output: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInput {
    pub outpoint: OutPoint,
    pub script_sig: Script,
    pub sequence: u32,
    pub witness: Vec<Script>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutput {
    pub value: Amount,
    pub pub_key: Script,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionV1 {
    pub version: i32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transaction {
    V1(TransactionV1), // TODO: add serialization index attribute
}

impl Idable for Transaction {
    fn get_id(&self) -> H256 {
        H256::zero()
    }
}
