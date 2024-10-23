// Copyright (c) 2024 RBB S.r.l
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

use common::{
    chain::{
        signature::inputsig::arbitrary_message::ArbitraryMessageSignature, Destination,
        SignedTransaction, Transaction,
    },
    primitives::{Id, Idable as _},
};
use serialization::{Decode, Encode};
use utils::ensure;

use crate::{WalletError, WalletResult};

#[derive(Debug, Clone, Encode, Decode)]
pub struct SignedTransactionIntent {
    signed_message: String,
    signatures: Vec<ArbitraryMessageSignature>,
}

impl SignedTransactionIntent {
    pub fn new<Signer>(
        transaction: &Transaction,
        input_destinations: &[Destination],
        intent_str: &str,
        signer: Signer,
    ) -> WalletResult<Self>
    where
        Signer: FnMut(
            /*message_to_sign:*/ &[u8],
            &Destination,
        ) -> WalletResult<ArbitraryMessageSignature>,
    {
        ensure!(
            transaction.inputs().len() == input_destinations.len(),
            WalletError::InvalidDestinationsCount {
                expected: transaction.inputs().len(),
                actual: input_destinations.len()
            }
        );

        Self::new_from_tx_id(
            &transaction.get_id(),
            input_destinations,
            intent_str,
            signer,
        )
    }

    pub fn new_from_tx_id<Signer>(
        tx_id: &Id<Transaction>,
        input_destinations: &[Destination],
        intent_str: &str,
        mut signer: Signer,
    ) -> WalletResult<Self>
    where
        Signer: FnMut(
            /*message_to_sign:*/ &[u8],
            &Destination,
        ) -> WalletResult<ArbitraryMessageSignature>,
    {
        let message_to_sign = Self::get_message_to_sign(intent_str, tx_id);

        let signatures = input_destinations
            .iter()
            .map(|dest| signer(message_to_sign.as_bytes(), dest))
            .collect::<WalletResult<Vec<_>>>()?;

        Ok(SignedTransactionIntent {
            signed_message: message_to_sign,
            signatures,
        })
    }

    pub fn signed_message(&self) -> &str {
        &self.signed_message
    }

    pub fn signatures(&self) -> &[ArbitraryMessageSignature] {
        &self.signatures
    }

    pub fn get_message_to_sign(intent: &str, tx_id: &Id<Transaction>) -> String {
        format!("tx:{tx_id:x};intent:{intent}")
    }
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct SignedTransactionWithIntent {
    pub transaction: SignedTransaction,
    pub intent: Option<SignedTransactionIntent>,
}
