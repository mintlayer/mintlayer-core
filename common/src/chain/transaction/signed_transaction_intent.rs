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

use crypto::key::{PrivateKey, SigAuxDataProvider};
use serialization::{Decode, Encode};
use utils::ensure;

use crate::{
    chain::{
        signature::inputsig::arbitrary_message::{
            self, ArbitraryMessageSignature, ArbitraryMessageSignatureRef,
        },
        ChainConfig, Destination, Transaction,
    },
    primitives::{Id, Idable as _},
};

use super::signature::{
    inputsig::arbitrary_message::SignArbitraryMessageError, DestinationSigError,
};

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
///
/// Note: for both `PublicKeyHash` and `PublicKey` destinations, the signature produced by "produce_" and expected by "verify_"
/// is `AuthorizedPublicKeyHashSpend`. This approach was chosen to simplify use-cases where `SignedTransactionIntent`
/// has to be produced manually (such as the wasm bindings).
/// TODO: the distinction between `AuthorizedPublicKeyHashSpend` and `AuthorizedPublicKeySpend` is not really useful for signatures
/// that are not supposed to be included in the blockchain, so probably `ArbitraryMessageSignature` itself could always
/// produce `AuthorizedPublicKeyHashSpend` for uniparty destinations.
#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq)]
pub struct SignedTransactionIntent {
    signed_message: String,
    // Note: the inner Vec is the result of `ArbitraryMessageSignature::into_raw`
    // (`ArbitraryMessageSignature` itself is deliberately not encodable).
    signatures: Vec<Vec<u8>>,
}

impl SignedTransactionIntent {
    pub fn from_components(
        signed_message: String,
        signatures: Vec<Vec<u8>>,
        input_destinations: &[Destination],
        chain_config: &ChainConfig,
    ) -> Result<Self, SignedTransactionIntentError> {
        let intent = Self {
            signed_message,
            signatures,
        };

        intent.verify(chain_config, input_destinations, intent.signed_message())?;

        Ok(intent)
    }

    /// Create a signed intent given the id of the transaction and its input destinations.
    ///
    /// Only PublicKeyHash and PublicKey destinations are supported by this function.
    pub fn produce_from_transaction_id<KeyGetter, Error, AuxP>(
        tx_id: &Id<Transaction>,
        input_destinations: &[Destination],
        intent_str: &str,
        mut prv_key_getter: KeyGetter,
        sig_aux_data_provider: &mut AuxP,
    ) -> Result<Self, Error>
    where
        KeyGetter: FnMut(&Destination) -> Result<PrivateKey, Error>,
        Error: From<SignedTransactionIntentError>,
        AuxP: SigAuxDataProvider + ?Sized,
    {
        let message_to_sign = Self::get_message_to_sign(intent_str, tx_id);

        let signatures = input_destinations
            .iter()
            .map(|dest| {
                match dest {
                    Destination::PublicKeyHash(_) | Destination::PublicKey(_) => {}

                    Destination::AnyoneCanSpend
                    | Destination::ScriptHash(_)
                    | Destination::ClassicMultisig(_) => {
                        return Err(SignedTransactionIntentError::UnsupportedDestination(
                            dest.clone(),
                        )
                        .into());
                    }
                }

                let prv_key = prv_key_getter(dest)?;
                let sig =
                    ArbitraryMessageSignature::produce_uniparty_signature_as_pub_key_hash_spending(
                        &prv_key,
                        message_to_sign.as_bytes(),
                        sig_aux_data_provider,
                    )
                    .map_err(SignedTransactionIntentError::MessageSigningError)?;

                Ok(sig.into_raw())
            })
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(SignedTransactionIntent {
            signed_message: message_to_sign,
            signatures,
        })
    }

    /// Same as `produce_from_transaction_id`, but this one accepts the whole transaction instead of just an id
    /// and performs an additional check - that the number of passed destinations matches the number of
    /// transaction inputs.
    pub fn produce_from_transaction<KeyGetter, Error, AuxP>(
        transaction: &Transaction,
        input_destinations: &[Destination],
        intent_str: &str,
        prv_key_getter: KeyGetter,
        sig_aux_data_provider: &mut AuxP,
    ) -> Result<Self, Error>
    where
        KeyGetter: FnMut(&Destination) -> Result<PrivateKey, Error>,
        Error: From<SignedTransactionIntentError>,
        AuxP: SigAuxDataProvider + ?Sized,
    {
        ensure!(
            transaction.inputs().len() == input_destinations.len(),
            SignedTransactionIntentError::InvalidDestinationsCount {
                expected: transaction.inputs().len(),
                actual: input_destinations.len()
            }
        );

        Self::produce_from_transaction_id(
            &transaction.get_id(),
            input_destinations,
            intent_str,
            prv_key_getter,
            sig_aux_data_provider,
        )
    }

    pub fn from_components_unchecked(signed_message: String, signatures: Vec<Vec<u8>>) -> Self {
        Self {
            signed_message,
            signatures,
        }
    }

    pub fn verify(
        &self,
        chain_config: &ChainConfig,
        input_destinations: &[Destination],
        expected_signed_message: &str,
    ) -> Result<(), SignedTransactionIntentError> {
        ensure!(
            self.signed_message == expected_signed_message,
            SignedTransactionIntentError::WrongSignedMessage {
                expected: expected_signed_message.to_owned(),
                actual: self.signed_message.clone()
            }
        );

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
            let destination = Self::normalize_destination(destination);

            let signature = ArbitraryMessageSignatureRef::from_data(signature);

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

    pub fn signatures(&self) -> &[Vec<u8>] {
        &self.signatures
    }

    pub fn get_message_to_sign(intent: &str, tx_id: &Id<Transaction>) -> String {
        format!("<tx_id:{tx_id:x};intent:{intent}>")
    }

    /// Converts PublicKey to PublicKeyHash destination
    pub fn normalize_destination(destination: &Destination) -> Destination {
        match destination {
            | Destination::PublicKey(pubkey) => Destination::PublicKeyHash(pubkey.into()),

            dest @ (Destination::PublicKeyHash(_)
            | Destination::AnyoneCanSpend
            | Destination::ScriptHash(_)
            | Destination::ClassicMultisig(_)) => dest.clone(),
        }
    }
}

#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum SignedTransactionIntentError {
    #[error("Wrong signed message: expected '{expected}', got '{actual}'")]
    WrongSignedMessage { expected: String, actual: String },

    #[error("Invalid destinations count: expected {expected}, got {actual}")]
    InvalidDestinationsCount { expected: usize, actual: usize },

    #[error("Message signing error: {0}")]
    MessageSigningError(SignArbitraryMessageError),

    #[error("Signature verification error for input {input_index}: {error}")]
    SignatureVerificationError {
        input_index: u32,
        error: DestinationSigError,
    },

    #[error("Unsupported destination: {0:?}")]
    UnsupportedDestination(Destination),
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, str::FromStr as _};

    use itertools::Itertools as _;
    use rstest::rstest;

    use crypto::key::{KeyKind, PrivateKey};
    use randomness::Rng;
    use test_utils::{
        assert_matches,
        random::{make_seedable_rng, Seed},
        random_ascii_alphanumeric_string,
    };

    use crate::{
        address::pubkeyhash::PublicKeyHash,
        chain::{config, Destination, OutPointSourceId, Transaction, TxInput},
        primitives::H256,
    };

    use super::*;

    #[test]
    fn get_message_to_sign_test() {
        let tx_id = Id::new(
            H256::from_str("DFC2BB0CC4C7F3ED3FE682A48EE9F78BCD4962E55E7BC239BD340EC22AFF8657")
                .unwrap(),
        );
        let message = SignedTransactionIntent::get_message_to_sign("test intent", &tx_id);
        let expected_message =
            "<tx_id:dfc2bb0cc4c7f3ed3fe682a48ee9f78bcd4962e55e7bc239bd340ec22aff8657;intent:test intent>";
        assert_eq!(message, expected_message);
    }

    // Basic check for signing and verification.
    // Also check that:
    // 1) using `produce_from_transaction` and `produce_from_transaction_id` gives the same result;
    // 2) `Destination::PublicKeyHash` and `PublicKey` can be used interchangeably;
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn signing_verification_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let chain_config = config::create_unit_test_config();

        for _ in 0..10 {
            let inputs_count = rng.gen_range(1..=10);
            let mut prv_keys = BTreeMap::new();

            let (input_destinations, flipped_input_destinations): (Vec<_>, Vec<_>) = (0
                ..inputs_count)
                .map(|_| {
                    let (prv_key, pub_key) =
                        PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
                    let pub_key_hash_dest = Destination::PublicKeyHash((&pub_key).into());
                    let pub_key_dest = Destination::PublicKey(pub_key);

                    prv_keys.insert(pub_key_dest.clone(), prv_key.clone());
                    prv_keys.insert(pub_key_hash_dest.clone(), prv_key);

                    if rng.gen_bool(0.5) {
                        (pub_key_dest, pub_key_hash_dest)
                    } else {
                        (pub_key_hash_dest, pub_key_dest)
                    }
                })
                .unzip();
            let other_destination = {
                let (prv_key, pub_key) =
                    PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

                let dest = if rng.gen_bool(0.5) {
                    Destination::PublicKey(pub_key)
                } else {
                    Destination::PublicKeyHash((&pub_key).into())
                };

                prv_keys.insert(dest.clone(), prv_key);
                dest
            };

            let tx_inputs = (0..inputs_count)
                .map(|_| {
                    let tx_id = Id::new(H256::random_using(&mut rng));
                    let idx = rng.gen_range(0..10);
                    TxInput::from_utxo(OutPointSourceId::Transaction(tx_id), idx)
                })
                .collect_vec();

            let tx = Transaction::new(0, tx_inputs, vec![]).unwrap();
            let tx_id = tx.get_id();
            let intent_str = random_ascii_alphanumeric_string(&mut rng, 1..100);
            let expected_signed_message =
                SignedTransactionIntent::get_message_to_sign(&intent_str, &tx_id);
            // Use the same state of rng for all "produce_" calls to be able to compare the signatures.
            let signer_rng_seed = rng.gen();

            let signed_intent1 = SignedTransactionIntent::produce_from_transaction(
                &tx,
                &input_destinations,
                &intent_str,
                |dest| Ok::<_, SignedTransactionIntentError>(prv_keys.get(dest).unwrap().clone()),
                &mut make_seedable_rng(signer_rng_seed),
            )
            .unwrap();

            let signed_intent2 = SignedTransactionIntent::produce_from_transaction_id(
                &tx_id,
                &input_destinations,
                &intent_str,
                |dest| Ok::<_, SignedTransactionIntentError>(prv_keys.get(dest).unwrap().clone()),
                &mut make_seedable_rng(signer_rng_seed),
            )
            .unwrap();

            let signed_intent3 = SignedTransactionIntent::produce_from_transaction(
                &tx,
                &flipped_input_destinations,
                &intent_str,
                |dest| Ok::<_, SignedTransactionIntentError>(prv_keys.get(dest).unwrap().clone()),
                &mut make_seedable_rng(signer_rng_seed),
            )
            .unwrap();

            let signed_intent4 = SignedTransactionIntent::produce_from_transaction_id(
                &tx_id,
                &flipped_input_destinations,
                &intent_str,
                |dest| Ok::<_, SignedTransactionIntentError>(prv_keys.get(dest).unwrap().clone()),
                &mut make_seedable_rng(signer_rng_seed),
            )
            .unwrap();

            assert_eq!(signed_intent1, signed_intent2);
            assert_eq!(signed_intent1, signed_intent3);
            assert_eq!(signed_intent1, signed_intent4);

            signed_intent1
                .verify(&chain_config, &input_destinations, &expected_signed_message)
                .unwrap();
            signed_intent1
                .verify(
                    &chain_config,
                    &flipped_input_destinations,
                    &expected_signed_message,
                )
                .unwrap();

            let wrong_message = "wrong message";
            let err = signed_intent1
                .verify(&chain_config, &input_destinations, wrong_message)
                .unwrap_err();
            assert_eq!(
                err,
                SignedTransactionIntentError::WrongSignedMessage {
                    expected: wrong_message.to_owned(),
                    actual: expected_signed_message.clone()
                }
            );

            let input_index_to_replace = rng.gen_range(0..input_destinations.len());

            let input_destinations_replaced = {
                let mut destinations = input_destinations.clone();
                destinations[input_index_to_replace] = other_destination;
                destinations
            };

            let err = signed_intent1
                .verify(
                    &chain_config,
                    &input_destinations_replaced,
                    &expected_signed_message,
                )
                .unwrap_err();
            assert_matches!(
                err,
                SignedTransactionIntentError::SignatureVerificationError {
                    input_index,
                    error: _
                } if input_index == input_index_to_replace as u32
            );
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn invalid_destinations_count_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let total_destinations_count = rng.gen_range(2..=10);

        let input_destinations = (0..total_destinations_count)
            .map(|_| {
                let (_prv_key, pub_key) =
                    PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
                Destination::PublicKey(pub_key)
            })
            .collect_vec();

        let tx_inputs = (0..total_destinations_count - 1)
            .map(|_| {
                let tx_id = Id::new(H256::random_using(&mut rng));
                let idx = rng.gen_range(0..10);
                TxInput::from_utxo(OutPointSourceId::Transaction(tx_id), idx)
            })
            .collect_vec();

        let intent_str = random_ascii_alphanumeric_string(&mut rng, 1..100);
        let tx = Transaction::new(0, tx_inputs, vec![]).unwrap();

        let err = SignedTransactionIntent::produce_from_transaction(
            &tx,
            &input_destinations,
            &intent_str,
            |_| -> Result<_, SignedTransactionIntentError> { panic!("shouldn't get this far") },
            &mut rng,
        )
        .unwrap_err();
        assert_eq!(
            err,
            SignedTransactionIntentError::InvalidDestinationsCount {
                expected: total_destinations_count - 1,
                actual: total_destinations_count
            }
        );

        let err = SignedTransactionIntent::produce_from_transaction(
            &tx,
            &input_destinations[..total_destinations_count - 2],
            &intent_str,
            |_| -> Result<_, SignedTransactionIntentError> { panic!("shouldn't get this far") },
            &mut rng,
        )
        .unwrap_err();
        assert_eq!(
            err,
            SignedTransactionIntentError::InvalidDestinationsCount {
                expected: total_destinations_count - 1,
                actual: total_destinations_count - 2
            }
        );
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn unsupported_destination_when_signing_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let destinations_count = rng.gen_range(2..=10);
        let mut prv_keys = BTreeMap::new();

        let orig_destinations = (0..destinations_count)
            .map(|_| {
                let (prv_key, pub_key) =
                    PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
                let dest = Destination::PublicKey(pub_key);
                prv_keys.insert(dest.clone(), prv_key);
                dest
            })
            .collect_vec();

        let tx_inputs = (0..destinations_count)
            .map(|_| {
                let tx_id = Id::new(H256::random_using(&mut rng));
                let idx = rng.gen_range(0..10);
                TxInput::from_utxo(OutPointSourceId::Transaction(tx_id), idx)
            })
            .collect_vec();

        let intent_str = random_ascii_alphanumeric_string(&mut rng, 1..100);
        let tx = Transaction::new(0, tx_inputs, vec![]).unwrap();
        let tx_id = tx.get_id();

        let unsupported_destinations = vec![
            Destination::AnyoneCanSpend,
            Destination::ScriptHash(Id::new(H256::random_using(&mut rng))),
            Destination::ClassicMultisig(PublicKeyHash::random_using(&mut rng)),
        ];
        let dest_index_to_replace = rng.gen_range(0..destinations_count);

        for unsupported_destination in unsupported_destinations {
            let mut destinations = orig_destinations.clone();
            destinations[dest_index_to_replace] = unsupported_destination.clone();

            let err = SignedTransactionIntent::produce_from_transaction(
                &tx,
                &destinations,
                &intent_str,
                |dest| Ok::<_, SignedTransactionIntentError>(prv_keys.get(dest).unwrap().clone()),
                &mut rng,
            )
            .unwrap_err();
            assert_eq!(
                err,
                SignedTransactionIntentError::UnsupportedDestination(
                    unsupported_destination.clone()
                )
            );

            let err = SignedTransactionIntent::produce_from_transaction_id(
                &tx_id,
                &destinations,
                &intent_str,
                |dest| Ok::<_, SignedTransactionIntentError>(prv_keys.get(dest).unwrap().clone()),
                &mut rng,
            )
            .unwrap_err();
            assert_eq!(
                err,
                SignedTransactionIntentError::UnsupportedDestination(unsupported_destination)
            );
        }
    }
}
