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
    chain::{
        classic_multisig::ClassicMultisigChallenge,
        signature::{
            inputsig::classical_multisig::multisig_partial_signature::PartiallySignedMultisigChallenge,
            TransactionSigError,
        },
        ChainConfig,
    },
    primitives::H256,
};

pub enum ClassicalMultisigCompletion {
    Complete(AuthorizedClassicalMultisigSpend),
    Incomplete(AuthorizedClassicalMultisigSpend),
}

#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
pub struct AuthorizedClassicalMultisigSpend {
    signatures: BTreeMap<u8, Signature>,
}

impl AuthorizedClassicalMultisigSpend {
    pub fn new_empty() -> Self {
        Self {
            signatures: BTreeMap::new(),
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

    pub fn new(signatures: BTreeMap<u8, Signature>) -> Self {
        Self { signatures }
    }
}

pub fn verify_classical_multisig_spending(
    chain_config: &ChainConfig,
    spendee_challenge: &ClassicMultisigChallenge,
    spender_signature: &AuthorizedClassicalMultisigSpend,
    sighash: &H256,
) -> Result<(), TransactionSigError> {
    let msg = sighash.encode();
    let verifier = PartiallySignedMultisigChallenge::from_partial(
        chain_config,
        spendee_challenge,
        &msg,
        spender_signature,
    )?;

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
) -> Result<ClassicalMultisigCompletion, TransactionSigError> {
    // ensure the challenge is valid before signing it
    if let Err(ch_err) = challenge.is_valid(chain_config) {
        return Err(
            TransactionSigError::AttemptedToSignClassicalMultisigWithInvalidChallenge(ch_err),
        );
    }

    // Ensure the signature doesn't already exist
    if current_signatures.signatures().get(&key_index).is_some() {
        return Err(TransactionSigError::ClassicalMultisigIndexAlreadyExists(
            key_index,
        ));
    }

    let msg = sighash.encode();

    {
        let verifier = PartiallySignedMultisigChallenge::from_partial(
            chain_config,
            challenge,
            &msg,
            &current_signatures,
        )?;

        // ensure the current signatures are valid before signing it
        match verifier.verify_signatures(chain_config)? {
            super::multisig_partial_signature::SigsVerifyResult::CompleteAndValid => {
                return Err(TransactionSigError::AttemptedToSignAlreadyCompleteClassicalMultisig)
            }
            super::multisig_partial_signature::SigsVerifyResult::Incomplete => (),
            super::multisig_partial_signature::SigsVerifyResult::Invalid => {
                return Err(
                    TransactionSigError::AttemptedToSignClassicalMultisigWithInvalidSignature,
                )
            }
        }
    }

    let spendee_pubkey = match challenge.public_keys().get(key_index as usize) {
        Some(k) => k,
        None => {
            return Err(TransactionSigError::InvalidClassicalMultisigKeyIndex(
                key_index,
                challenge.public_keys().len(),
            ))
        }
    };

    // Ensure the given private key matches the public key at the given index
    let calculated_public_key = crypto::key::PublicKey::from_private_key(private_key);
    if *spendee_pubkey != calculated_public_key {
        return Err(TransactionSigError::SpendeePrivatePublicKeyMismatch);
    }
    let signature = private_key
        .sign_message(&msg)
        .map_err(TransactionSigError::ProducingSignatureFailed)?;

    let mut current_signatures = current_signatures;

    current_signatures.add_signature(key_index, signature);

    // Check the signatures status again after adding that last signature
    let verifier = PartiallySignedMultisigChallenge::from_partial(
        chain_config,
        challenge,
        &msg,
        &current_signatures,
    )?;

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
    fn basic(#[case] seed: Seed) {
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

        let mut current_signatures = AuthorizedClassicalMultisigSpend::new_empty();

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
            current_signatures = match (total_parties as usize - indices_to_sign.len())
                .cmp(&(min_required_signatures.get() as usize))
            {
                Ordering::Less => match res {
                    Ok(ClassicalMultisigCompletion::Complete(_sigs)) => {
                        unreachable!("The signatures should be incomplete at this point");
                    }
                    Ok(ClassicalMultisigCompletion::Incomplete(sigs)) => sigs,
                    Err(e) => panic!("Unexpected error: {:?}", e),
                },
                Ordering::Equal => match res {
                    Ok(ClassicalMultisigCompletion::Complete(sigs)) => sigs,
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
                        TransactionSigError::AttemptedToSignAlreadyCompleteClassicalMultisig => {
                            current_signatures
                        }
                        _ => panic!("Unexpected error: {:?}", e),
                    },
                },
            };
        }
    }
}
