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
use wallet_types::{
    partially_signed_transaction::PartiallySignedTransaction, signature_status::SignatureStatus,
};

use super::Balances;

pub enum TransactionToInspect {
    Tx(Transaction),
    Partial(PartiallySignedTransaction),
    Signed(SignedTransaction),
}

#[derive(Debug, Clone)]
pub struct ValidatedSignatures {
    pub num_valid_signatures: usize,
    pub num_invalid_signatures: usize,
    pub signature_statuses: Vec<SignatureStatus>,
}

impl ValidatedSignatures {
    pub fn new(signature_statuses: Vec<SignatureStatus>) -> Self {
        let num_valid_signatures = signature_statuses
            .iter()
            .copied()
            .filter(|x| *x == SignatureStatus::FullySigned)
            .count();
        let num_invalid_signatures = signature_statuses
            .iter()
            .copied()
            .filter(|x| *x == SignatureStatus::InvalidSignature)
            .count();

        Self {
            num_valid_signatures,
            num_invalid_signatures,
            signature_statuses,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignatureStats {
    pub num_inputs: usize,
    pub total_signatures: usize,
    pub validated_signatures: Option<ValidatedSignatures>,
}

#[derive(Debug, Clone)]
pub struct InspectTransaction {
    pub tx: HexEncoded<Transaction>,
    pub fees: Option<Balances>,
    pub stats: SignatureStats,
}
