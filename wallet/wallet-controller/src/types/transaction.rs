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

use common::chain::{SignedTransaction, Transaction};
use serialization::hex_encoded::HexEncoded;
use wallet::account::PartiallySignedTransaction;

use super::Balances;

pub enum TransactionToInspect {
    Tx(Transaction),
    Partial(PartiallySignedTransaction),
    Signed(SignedTransaction),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidatedSignatures {
    pub num_valid_signatures: usize,
    pub num_invalid_signatures: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignatureStats {
    pub num_inputs: usize,
    pub total_signatures: usize,
    pub validated_signatures: Option<ValidatedSignatures>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InspectTransaction {
    pub tx: HexEncoded<Transaction>,
    pub fees: Option<Balances>,
    pub stats: SignatureStats,
}

impl rpc_description::HasValueHint for InspectTransaction {
    const HINT: rpc_description::ValueHint = rpc_description::ValueHint::Object(&[
        ("tx", &<HexEncoded<Transaction>>::HINT),
        ("fees", &<Option<Balances>>::HINT),
        ("stats", &rpc_description::ValueHint::GENERIC_OBJECT),
    ]);
}
