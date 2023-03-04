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
    match current_signatures.signatures().get(&key_index) {
        Some(_) => {
            return Err(TransactionSigError::ClassicalMultisigIndexAlreadyExists(
                key_index,
            ))
        }
        None => (),
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
