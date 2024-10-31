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
        signature::inputsig::arbitrary_message::{self, ArbitraryMessageSignature}, ChainConfig,
        Destination, Transaction,
    },
    primitives::{Id, Idable as _},
};

use super::signature::{inputsig::arbitrary_message::SignArbitraryMessageError, DestinationSigError};

/// `SignedTransactionIntent` acts as a proof that a certain transaction was created with the specific intent in mind.
/// This is achieved by combining the specified 'intent' string with the transaction id and signing it by private keys
/// corresponding to each of the transaction's input destinations.
///
/// For example, when bridging tokens to a foreign network, the user needs to send them to a bridge address
/// on the Mintlayer network and then inform the bridge, providing it with the transaction id and the address on the
/// foreign network where the tokens should be sent to. But this naive scheme allows an attacker to steal the tokens,
/// by creating a bridge request ahead of the user and specifying his own destination address instead.
/// To protect against this, the bridge would require the user to also provide it with a `SignedTransactionIntent` where
/// the 'intent' would be set to the user's destination address on the foreign network.
///
/// Note: technically, having only one signature corresponding to an arbitrary transaction input may also serve
/// as a proof of intent. However, it's much weaker and is potentially exploitable, e.g. if one of the transaction's
/// inputs comes from a compromised wallet. So we require a signature for each of the inputs.
/// But this puts a limitation on what transactions can have a `SignedTransactionIntent` or rather what inputs such transactions
/// are allowed to have - they must have exactly one associated destination. Though `SignedTransactionIntent` itself
/// doesn't specify how destinations are obtained from `TxOutput`, in practice only transactions with Transfer and
/// LockThenTransfer input destinations will be supported.
#[derive(Debug, Clone, Encode, Decode)]
pub struct SignedTransactionIntent {
    signed_message: String,
    signatures: Vec<ArbitraryMessageSignature>,
}

impl SignedTransactionIntent {
    /// Create a signed intent given the id of the transaction and its input destinations.
    /// 
    /// Only PublicKeyHash and PublicKey destinations are supported by this function.
    pub fn from_transaction_id<KeyGetter, Error, R>(
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

    /// Same as `from_transaction_id`, but this one accepts the whole transaction instead of just an id
    /// and performs an additional check - that the number of passed destinations matches the number of
    /// transaction inputs.
    pub fn from_transaction<KeyGetter, Error, R>(
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

        Self::from_transaction_id(
            &transaction.get_id(),
            input_destinations,
            intent_str,
            prv_key_getter,
            rng,
        )
    }

    pub fn from_components_unchecked(
        signed_message: String,
        signatures: Vec<ArbitraryMessageSignature>,
    ) -> Self {
        Self {
            signed_message,
            signatures,
        }
    }

    pub fn verify(
        &self,
        chain_config: &ChainConfig,
        input_destinations: &[Destination],
    ) -> Result<(), SignedTransactionIntentError> {
        ensure!(
            self.signatures.len() == input_destinations.len(),
            SignedTransactionIntentError::InvalidDestinationsCount {
                expected: self.signatures.len(),
                actual: input_destinations.len()
            }
        );

        let signed_challenge =
            arbitrary_message::produce_message_challenge(self.signed_message.as_bytes());

        for (idx, (signature, destination)) in
            self.signatures.iter().zip(input_destinations).enumerate()
        {
            signature
                .verify_signature(chain_config, &destination, &signed_challenge)
                .map_err(
                    |err| SignedTransactionIntentError::SignatureVerificationError {
                        input_index: idx as u32,
                        error: err,
                    },
                )?;
        }

        Ok(())
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

#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum SignedTransactionIntentError {
    #[error("Invalid destinations count: expected {expected}, got {actual}")]
    InvalidDestinationsCount { expected: usize, actual: usize },

    #[error("Message signing error: {0}")]
    MessageSigningError(SignArbitraryMessageError),

    #[error("Signature verification error for input {input_index}: {error}")]
    SignatureVerificationError {
        input_index: u32,
        error: DestinationSigError,
    },
}
