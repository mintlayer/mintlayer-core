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

//! (experimental) Per-transaction fees of a block, as computed by the
//! consensus layer during block connection and persisted for serving to
//! API consumers (the scanner stores them instead of recomputing fees).

use crate::primitives::{Fee, Id};

use serialization::{Decode, Encode};

use crate::chain::Transaction;

/// Fees of every transaction of a block, in block order.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, serde::Serialize, serde::Deserialize)]
pub struct BlockTxFees(pub Vec<(Id<Transaction>, Fee)>);

impl rpc_description::HasValueHint for BlockTxFees {
    const HINT_SER: rpc_description::ValueHint = rpc_description::ValueHint::GENERIC_OBJECT;
    const HINT_DE: rpc_description::ValueHint = rpc_description::ValueHint::GENERIC_OBJECT;
}

impl BlockTxFees {

}
