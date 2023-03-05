// Copyright (c) 2021-2023 RBB S.r.l
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

use std::collections::BTreeMap;

use crypto::key::Signature;
use serialization::{Decode, Encode};

use crate::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        classic_multisig::{ClassicMultisigChallenge, ClassicMultisigChallengeError},
        signature::{
            inputsig::classical_multisig::multisig_partial_signature::PartiallySignedMultisigChallenge,
            TransactionSigError,
        },
        ChainConfig,
    },
    primitives::H256,
};

use super::multisig_partial_signature::PartiallySignedMultisigStructureError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassicalMultisigCompletion {
    Complete(AuthorizedClassicalMultisigSpend),
    Incomplete(AuthorizedClassicalMultisigSpend),
}

/// A witness that represents the authorization to spend a classical multisig output.
#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
pub struct AuthorizedClassicalMultisigSpend {
    signatures: BTreeMap<u8, Signature>,
    challenge: ClassicMultisigChallenge,
}

impl AuthorizedClassicalMultisigSpend {
    pub fn new_empty(challenge: ClassicMultisigChallenge) -> Self {
        Self {
            signatures: BTreeMap::new(),
            challenge,
        }
    }

    pub fn available_signatures_count(&self) -> usize {
        self.signatures.len()
    }

    pub fn add_signature(&mut self, index: u8, signature: Signature) {
        self.signatures.insert(index, signature);
    }

    pub fn signatures(&self) -> &BTreeMap<u8, Signature> {
        &self.signatures
    }

    pub fn challenge(&self) -> &ClassicMultisigChallenge {
        &self.challenge
    }

    pub fn public_key_indices(&self) -> impl Iterator<Item = u8> + '_ {
        self.signatures.keys().copied()
    }

    pub fn take(self) -> BTreeMap<u8, Signature> {
        self.signatures
    }

    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (u8, &Signature)> + '_ {
        self.signatures.iter().map(|(k, v)| (*k, v))
    }

    pub fn from_data(data: &Vec<u8>) -> Result<Self, TransactionSigError> {
        let decoded = AuthorizedClassicalMultisigSpend::decode(&mut data.as_slice())
            .map_err(|_| TransactionSigError::InvalidSignatureEncoding)?;
        Ok(decoded)
    }

    pub fn new(signatures: BTreeMap<u8, Signature>, challenge: ClassicMultisigChallenge) -> Self {
        Self {
            signatures,
            challenge,
        }
    }
}

pub fn verify_classical_multisig_spending(
    chain_config: &ChainConfig,
    challenge_hash: &PublicKeyHash,
    spender_signature: &AuthorizedClassicalMultisigSpend,
    sighash: &H256,
) -> Result<(), TransactionSigError> {
    let msg = sighash.encode();

    let expected_hash: PublicKeyHash = spender_signature.challenge().into();
    if expected_hash != *challenge_hash {
        return Err(TransactionSigError::ClassicalMultisigWitnessHashMismatch);
    }

    let verifier =
        PartiallySignedMultisigChallenge::from_partial(chain_config, &msg, spender_signature)?;

    match verifier.verify_signatures(chain_config)? {
        super::multisig_partial_signature::SigsVerifyResult::CompleteAndValid => Ok(()),
        super::multisig_partial_signature::SigsVerifyResult::Incomplete => {
            Err(TransactionSigError::IncompleteClassicalMultisigSignature)
        }
        super::multisig_partial_signature::SigsVerifyResult::Invalid => {
            Err(TransactionSigError::InvalidClassicalMultisigSignature)
        }
    }
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum ClassicalMultisigSigningError {
    #[error("Attempted to sign a classical multisig with invalid challenge")]
    AttemptedToSignClassicalMultisigWithInvalidChallenge(ClassicMultisigChallengeError),
    #[error("Attempted to add a classical multisig with an index that already exists")]
    ClassicalMultisigIndexAlreadyExists(u8),
    #[error("Attempted to sign a classical multisig that is already complete")]
    AttemptedToSignAlreadyCompleteClassicalMultisig,
    #[error("Invalid classical multisig key index: {0} (must be in range 0..{1})")]
    InvalidClassicalMultisigKeyIndex(u8, usize),
    #[error("Attempted to sign a classical multisig with pre-existing invalid signature(s)")]
    AttemptedToSignClassicalMultisigWithInvalidSignature,
    #[error("Private key does not match with spender public key")]
    SpendeePrivatePublicKeyMismatch,
    #[error("Producing signature failed!")]
    ProducingSignatureFailed(crypto::key::SignatureError),
    #[error("Invalid classical multisig challenge")]
    InvalidClassicalMultisig(#[from] PartiallySignedMultisigStructureError),
}

/// Given a challenge, a private key, a sighash, and a set of current signatures, sign the challenge
/// at the given index. Classical multisig signatures are put in a map, where the key is the index,
/// and the value is the signature. Every call to this function adds one signature.
/// The returned value is a `ClassicalMultisigCompletion` enum, which can be either `Complete` or `Incomplete`,
/// indicating whether more signatures are needed to complete the multisig authorization.
/// A signature cannot be added more than once. Also, in every iteration, all the signatures must be valid,
/// and obviously the challenge must be valid too, since there is no point in adding signatures to anything
/// that is considered invalid.
pub fn sign_classical_multisig_spending(
    chain_config: &ChainConfig,
    key_index: u8,
    private_key: &crypto::key::PrivateKey,
    challenge: &ClassicMultisigChallenge,
    sighash: &H256,
    current_signatures: AuthorizedClassicalMultisigSpend,
) -> Result<ClassicalMultisigCompletion, ClassicalMultisigSigningError> {
    // ensure the challenge is valid before signing it
    if let Err(ch_err) = challenge.is_valid(chain_config) {
        return Err(
            ClassicalMultisigSigningError::AttemptedToSignClassicalMultisigWithInvalidChallenge(
                ch_err,
            ),
        );
    }

    // Ensure the signature doesn't already exist
    if current_signatures.signatures().get(&key_index).is_some() {
        return Err(ClassicalMultisigSigningError::ClassicalMultisigIndexAlreadyExists(key_index));
    }

    let msg = sighash.encode();

    {
        let verifier = PartiallySignedMultisigChallenge::from_partial(
            chain_config,
            &msg,
            &current_signatures,
        )?;

        // ensure the current signatures are valid before signing it
        match verifier.verify_signatures(chain_config)? {
            super::multisig_partial_signature::SigsVerifyResult::CompleteAndValid => {
                return Err(
                    ClassicalMultisigSigningError::AttemptedToSignAlreadyCompleteClassicalMultisig,
                )
            }
            super::multisig_partial_signature::SigsVerifyResult::Incomplete => (),
            super::multisig_partial_signature::SigsVerifyResult::Invalid => return Err(
                ClassicalMultisigSigningError::AttemptedToSignClassicalMultisigWithInvalidSignature,
            ),
        }
    }

    let spendee_pubkey = match challenge.public_keys().get(key_index as usize) {
        Some(k) => k,
        None => {
            return Err(
                ClassicalMultisigSigningError::InvalidClassicalMultisigKeyIndex(
                    key_index,
                    challenge.public_keys().len(),
                ),
            )
        }
    };

    // Ensure the given private key matches the public key at the given index
    let calculated_public_key = crypto::key::PublicKey::from_private_key(private_key);
    if *spendee_pubkey != calculated_public_key {
        return Err(ClassicalMultisigSigningError::SpendeePrivatePublicKeyMismatch);
    }
    let signature = private_key
        .sign_message(&msg)
        .map_err(ClassicalMultisigSigningError::ProducingSignatureFailed)?;

    let mut current_signatures = current_signatures;

    current_signatures.add_signature(key_index, signature);

    // Check the signatures status again after adding that last signature
    let verifier =
        PartiallySignedMultisigChallenge::from_partial(chain_config, &msg, &current_signatures)?;

    match verifier.verify_signatures(chain_config)? {
        super::multisig_partial_signature::SigsVerifyResult::CompleteAndValid => {
            Ok(ClassicalMultisigCompletion::Complete(current_signatures))
        }
        super::multisig_partial_signature::SigsVerifyResult::Incomplete => {
            Ok(ClassicalMultisigCompletion::Incomplete(current_signatures))
        }
        super::multisig_partial_signature::SigsVerifyResult::Invalid => {
            unreachable!(
                "We checked the signatures then added a signature, so this should be unreachable"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU8;

    use crypto::key::{KeyKind, PrivateKey};
    use crypto::random::{Rng, SliceRandom};
    use rstest::rstest;
    use std::cmp::Ordering;
    use test_utils::random::{make_seedable_rng, Seed};

    use crate::chain::config::create_mainnet;

    use super::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn gradual_signing(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let chain_config = create_mainnet();
        let min_required_signatures = (rng.gen::<u8>() % 10) + 1;
        let min_required_signatures: NonZeroU8 = min_required_signatures.try_into().unwrap();
        let total_parties = (rng.gen::<u8>() % 5) + min_required_signatures.get();
        let (priv_keys, pub_keys): (Vec<_>, Vec<_>) = (0..total_parties)
            .into_iter()
            .map(|_| PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr))
            .unzip();
        let challenge =
            ClassicMultisigChallenge::new(&chain_config, min_required_signatures, pub_keys)
                .unwrap();
        challenge.is_valid(&chain_config).unwrap();

        let sighash = H256::random_using(&mut rng);

        let mut indices_to_sign: Vec<_> = (0..total_parties).collect();
        indices_to_sign.shuffle(&mut rng);

        let mut current_signatures = AuthorizedClassicalMultisigSpend::new_empty(challenge.clone());

        // Keep signing and adding signatures, and expect to start failing when we reach the required number of signatures
        while let Some(key_index) = indices_to_sign.pop() {
            let private_key = &priv_keys[key_index as usize];

            let res = sign_classical_multisig_spending(
                &chain_config,
                key_index,
                private_key,
                &challenge,
                &sighash,
                current_signatures.clone(),
            );

            // When testing valid cases, depending on the number of already-done signatures, we have 3 possible results:
            // 1. We add a signature and the result is still incomplete
            // 2. We add a signature and the result is complete
            // 3. We add a signature, but we can't because the required signatures are already reached
            // In each case, we test the verification of signatures and the expected outcome
            current_signatures = match (total_parties as usize - indices_to_sign.len())
                .cmp(&(min_required_signatures.get() as usize))
            {
                Ordering::Less => match res {
                    Ok(ClassicalMultisigCompletion::Complete(_sigs)) => {
                        unreachable!("The signatures should be incomplete at this point");
                    }
                    Ok(ClassicalMultisigCompletion::Incomplete(sigs)) => {
                        {
                            // complete verification should pass
                            let correct_challenge_hash: PublicKeyHash = (&challenge).into();
                            assert_eq!(verify_classical_multisig_spending(
                                &chain_config,
                                &correct_challenge_hash,
                                &sigs,
                                &sighash,
                            )
                            .unwrap_err(), TransactionSigError::IncompleteClassicalMultisigSignature);
                        }
                        sigs
                    },
                    Err(e) => panic!("Unexpected error: {:?}", e),
                },
                Ordering::Equal => match res {
                    Ok(ClassicalMultisigCompletion::Complete(sigs)) => {
                        {
                            // complete verification should pass
                            let correct_challenge_hash: PublicKeyHash = (&challenge).into();
                            verify_classical_multisig_spending(
                                &chain_config,
                                &correct_challenge_hash,
                                &sigs,
                                &sighash,
                            )
                            .unwrap();
                        }
                        sigs
                    },
                    Ok(ClassicalMultisigCompletion::Incomplete(_sigs)) => {
                        unreachable!("The signatures should be complete at this point");
                    }
                    Err(e) => panic!("Unexpected error: {:?}", e),
                },
                Ordering::Greater => match res {
                    Ok(ClassicalMultisigCompletion::Complete(_sigs)) => {
                        unreachable!("The signatures should be complete at this point, so signing more shouldn't be possible");
                    }
                    Ok(ClassicalMultisigCompletion::Incomplete(_sigs)) => {
                        unreachable!("The signatures should be complete at this point");
                    }
                    Err(e) => match e {
                        ClassicalMultisigSigningError::AttemptedToSignAlreadyCompleteClassicalMultisig => {
                            {
                                // complete verification should pass. We try to sign, but nothing should change
                                let correct_challenge_hash: PublicKeyHash = (&challenge).into();
                                verify_classical_multisig_spending(
                                    &chain_config,
                                    &correct_challenge_hash,
                                    &current_signatures,
                                    &sighash,
                                )
                                .unwrap();
                            }
                            current_signatures
                        }
                        _ => panic!("Unexpected error: {:?}", e),
                    },
                },
            };
        }

        // Verify signatures with the correct hash
        let correct_challenge_hash: PublicKeyHash = (&challenge).into();
        verify_classical_multisig_spending(
            &chain_config,
            &correct_challenge_hash,
            &current_signatures,
            &sighash,
        )
        .unwrap();
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn tamper_with_data(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let chain_config = create_mainnet();
        let min_required_signatures = (rng.gen::<u8>() % 10) + 1;
        let min_required_signatures: NonZeroU8 = min_required_signatures.try_into().unwrap();
        let total_parties = (rng.gen::<u8>() % 5) + min_required_signatures.get();
        let (priv_keys, pub_keys): (Vec<_>, Vec<_>) = (0..total_parties)
            .into_iter()
            .map(|_| PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr))
            .unzip();
        let challenge =
            ClassicMultisigChallenge::new(&chain_config, min_required_signatures, pub_keys)
                .unwrap();
        challenge.is_valid(&chain_config).unwrap();

        let sighash = H256::random_using(&mut rng);

        // We create only the required signatures count
        let mut indices_to_sign: Vec<_> = (0..total_parties).collect();
        indices_to_sign.shuffle(&mut rng);
        let indices_to_sign =
            indices_to_sign.into_iter().take(min_required_signatures.get() as usize);
        assert_eq!(
            indices_to_sign.len(),
            min_required_signatures.get() as usize
        );

        // Keep signing and adding signatures until it's complete
        let mut current_signatures = AuthorizedClassicalMultisigSpend::new_empty(challenge.clone());
        for key_index in indices_to_sign {
            let private_key = &priv_keys[key_index as usize];

            let sign_res = sign_classical_multisig_spending(
                &chain_config,
                key_index,
                private_key,
                &challenge,
                &sighash,
                current_signatures.clone(),
            )
            .unwrap();

            match sign_res {
                ClassicalMultisigCompletion::Incomplete(sigs) => {
                    current_signatures = sigs;
                    // We still have to sign more
                    assert!(
                        current_signatures.signatures().len()
                            < min_required_signatures.get() as usize
                    );

                    {
                        // incomplete signatures should fail to verify with a specific error
                        let correct_challenge_hash: PublicKeyHash = (&challenge).into();
                        assert_eq!(
                            verify_classical_multisig_spending(
                                &chain_config,
                                &correct_challenge_hash,
                                &current_signatures,
                                &sighash,
                            )
                            .unwrap_err(),
                            TransactionSigError::IncompleteClassicalMultisigSignature
                        );
                    }
                }
                ClassicalMultisigCompletion::Complete(sigs) => {
                    current_signatures = sigs;
                    // We're done signing
                    assert_eq!(
                        current_signatures.signatures().len(),
                        min_required_signatures.get() as usize
                    );

                    {
                        // complete verification should pass
                        let correct_challenge_hash: PublicKeyHash = (&challenge).into();
                        verify_classical_multisig_spending(
                            &chain_config,
                            &correct_challenge_hash,
                            &current_signatures,
                            &sighash,
                        )
                        .unwrap();
                    }
                }
            };
        }

        // Verify signatures with the correct hash
        let correct_challenge_hash: PublicKeyHash = (&challenge).into();
        verify_classical_multisig_spending(
            &chain_config,
            &correct_challenge_hash,
            &current_signatures,
            &sighash,
        )
        .unwrap();

        {
            // Tamper with the challenge hash
            let mut wrong_hash_vec = correct_challenge_hash;
            let wrong_hash_vec = wrong_hash_vec.as_mut();
            wrong_hash_vec[0] = wrong_hash_vec[0].wrapping_add(1);
            let wrong_challenge_hash = PublicKeyHash::try_from(wrong_hash_vec.to_vec()).unwrap();

            assert_eq!(
                verify_classical_multisig_spending(
                    &chain_config,
                    &wrong_challenge_hash,
                    &current_signatures,
                    &sighash,
                )
                .unwrap_err(),
                TransactionSigError::ClassicalMultisigWitnessHashMismatch
            );
        }

        {
            // Tamper with a signature, by signing using a new random private key
            let current_signatures = current_signatures;
            let mut available_key_indexes =
                current_signatures.signatures().keys().collect::<Vec<_>>();
            available_key_indexes.shuffle(&mut rng);
            let tampered_with_key_index = available_key_indexes[0];
            let (new_random_private_key, _) =
                PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let mut signatures = current_signatures.signatures().clone();

            signatures.insert(
                *tampered_with_key_index,
                new_random_private_key.sign_message(&sighash.encode()).unwrap(),
            );

            let current_signatures = AuthorizedClassicalMultisigSpend::new(
                signatures,
                current_signatures.challenge().clone(),
            );

            // Verify and expect to fail
            let correct_challenge_hash: PublicKeyHash = (&challenge).into();
            assert_eq!(
                verify_classical_multisig_spending(
                    &chain_config,
                    &correct_challenge_hash,
                    &current_signatures,
                    &sighash,
                )
                .unwrap_err(),
                TransactionSigError::InvalidClassicalMultisigSignature
            );
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn signing_errors(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let chain_config = create_mainnet();
        let min_required_signatures = (rng.gen::<u8>() % 10) + 1;
        let min_required_signatures: NonZeroU8 = min_required_signatures.try_into().unwrap();
        let total_parties = (rng.gen::<u8>() % 5) + min_required_signatures.get();
        let (priv_keys, pub_keys): (Vec<_>, Vec<_>) = (0..total_parties)
            .into_iter()
            .map(|_| PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr))
            .unzip();
        let challenge =
            ClassicMultisigChallenge::new(&chain_config, min_required_signatures, pub_keys)
                .unwrap();
        challenge.is_valid(&chain_config).unwrap();

        let sighash = H256::random_using(&mut rng);

        // We create only the required signatures count
        let mut indices_to_sign: Vec<_> = (0..total_parties).collect();
        indices_to_sign.shuffle(&mut rng);
        let indices_to_sign =
            indices_to_sign.into_iter().take(min_required_signatures.get() as usize);
        assert_eq!(
            indices_to_sign.len(),
            min_required_signatures.get() as usize
        );

        // Keep signing and adding signatures until it's complete
        let current_signatures = AuthorizedClassicalMultisigSpend::new_empty(challenge.clone());

        // Signatures should fail if the challenge is not valid
        // Tamper with challenge serialization, make it invalid, and try to use it
        {
            let mut encoded_challenge = challenge.encode();
            encoded_challenge[0] = 0; // tamper with the challenge, first byte is min_required_signatures
            let invalid_challenge =
                ClassicMultisigChallenge::decode(&mut encoded_challenge.as_slice()).unwrap();

            let key_index = rng.gen::<u8>() % total_parties;
            let private_key = &priv_keys[key_index as usize];

            let sign_err = sign_classical_multisig_spending(
                &chain_config,
                key_index,
                private_key,
                &invalid_challenge,
                &sighash,
                current_signatures.clone(),
            )
            .unwrap_err();

            assert_eq!(
                sign_err,
                ClassicalMultisigSigningError::AttemptedToSignClassicalMultisigWithInvalidChallenge(
                    ClassicMultisigChallengeError::MinRequiredSignaturesIsZero
                )
            );
        }
    }
}
