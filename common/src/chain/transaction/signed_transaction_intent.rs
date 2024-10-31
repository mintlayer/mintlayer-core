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

use crypto::key::PrivateKey;
use randomness::{CryptoRng, Rng};
use serialization::{Decode, Encode};
use utils::ensure;

use crate::{
    chain::{
        signature::inputsig::arbitrary_message::ArbitraryMessageSignature, Destination, Transaction,
    },
    primitives::{Id, Idable as _},
};

use super::signature::inputsig::arbitrary_message::SignArbitraryMessageError;

#[derive(Debug, Clone, Encode, Decode)]
pub struct SignedTransactionIntent {
    signed_message: String,
    signatures: Vec<ArbitraryMessageSignature>,
}

impl SignedTransactionIntent {
    pub fn new<KeyGetter, Error, R>(
        transaction: &Transaction,
        input_destinations: &[Destination],
        intent_str: &str,
        prv_key_getter: KeyGetter,
        rng: R,
    ) -> Result<Self, Error>
    where
        KeyGetter: FnMut(&Destination) -> Result<PrivateKey, Error>,
        Error: From<SignedTransactionIntentError>,
        R: Rng + CryptoRng,
    {
        ensure!(
            transaction.inputs().len() == input_destinations.len(),
            SignedTransactionIntentError::InvalidDestinationsCount {
                expected: transaction.inputs().len(),
                actual: input_destinations.len()
            }
        );

        Self::new_from_tx_id(
            &transaction.get_id(),
            input_destinations,
            intent_str,
            prv_key_getter,
            rng,
        )
    }

    pub fn new_from_tx_id<KeyGetter, Error, R>(
        tx_id: &Id<Transaction>,
        input_destinations: &[Destination],
        intent_str: &str,
        mut prv_key_getter: KeyGetter,
        mut rng: R,
    ) -> Result<Self, Error>
    where
        KeyGetter: FnMut(&Destination) -> Result<PrivateKey, Error>,
        Error: From<SignedTransactionIntentError>,
        R: Rng + CryptoRng,
    {
        let message_to_sign = Self::get_message_to_sign(intent_str, tx_id);

        let signatures = input_destinations
            .iter()
            .map(|dest| {
                let prv_key = prv_key_getter(dest)?;
                let sig = ArbitraryMessageSignature::produce_uniparty_signature(
                    &prv_key,
                    dest,
                    message_to_sign.as_bytes(),
                    &mut rng,
                )
                .map_err(SignedTransactionIntentError::MessageSigningError)?;

                Ok(sig)
            })
            .collect::<Result<Vec<_>, Error>>()?;

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

#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum SignedTransactionIntentError {
    #[error("Invalid destinations count: expected {expected}, got {actual}")]
    InvalidDestinationsCount { expected: usize, actual: usize },

    #[error("Message signing error: {0}")]
    MessageSigningError(SignArbitraryMessageError),
}
