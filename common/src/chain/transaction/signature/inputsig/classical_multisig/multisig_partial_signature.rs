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

use crate::chain::{
    classic_multisig::{ClassicMultisigChallenge, ClassicMultisigChallengeError},
    ChainConfig,
};

use super::authorize_classical_multisig::AuthorizedClassicalMultisigSpend;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartiallySignedMultisigChallenge<'a> {
    /// The signatures that have been added to this challenge. The indices are the indices of the public keys.
    signatures: &'a AuthorizedClassicalMultisigSpend,
    /// The message that is being signed.
    message: &'a [u8],
    /// The challenge that is being signed.
    challenge: &'a ClassicMultisigChallenge,
}

impl<'a> PartiallySignedMultisigChallenge<'a> {
    pub fn from_partial(
        chain_config: &ChainConfig,
        challenge: &'a ClassicMultisigChallenge,
        message: &'a [u8],
        signatures: &'a AuthorizedClassicalMultisigSpend,
    ) -> Result<Self, PartiallySignedMultisigStructureError> {
        let result = PartiallySignedMultisigChallenge {
            signatures,
            challenge,
            message,
        };
        result.check_structurally_valid(chain_config)?;
        Ok(result)
    }

    pub fn challenge(&self) -> &ClassicMultisigChallenge {
        self.challenge
    }

    pub fn signatures(&self) -> &AuthorizedClassicalMultisigSpend {
        self.signatures
    }

    pub fn missing_signatures_count(&self) -> i32 {
        self.challenge.min_required_signatures() as i32
            - self.signatures.available_signatures_count() as i32
    }

    /// Check whether the structure of the multisig challenge and signatures is valid, but without validating signatures
    pub fn check_structurally_valid(
        &self,
        chain_config: &ChainConfig,
    ) -> Result<PartiallySignedMultisigState, PartiallySignedMultisigStructureError> {
        if let Err(err) = self.challenge.is_valid(chain_config) {
            return Err(PartiallySignedMultisigStructureError::InvalidChallenge(err));
        }

        if self
            .signatures
            .public_key_indices()
            .any(|index| index as usize >= self.challenge.public_keys().len())
        {
            return Err(PartiallySignedMultisigStructureError::InvalidSignatureIndex);
        }

        let missing_signatures_count = self.missing_signatures_count();
        match missing_signatures_count.cmp(&0) {
            std::cmp::Ordering::Less => {
                Err(PartiallySignedMultisigStructureError::Overconstrained(
                    self.signatures.available_signatures_count(),
                    self.challenge.min_required_signatures() as usize,
                ))
            }
            std::cmp::Ordering::Equal => Ok(PartiallySignedMultisigState::Complete(
                self.signatures.available_signatures_count(),
            )),
            std::cmp::Ordering::Greater => Ok(PartiallySignedMultisigState::Incomplete(
                self.signatures.available_signatures_count(),
                self.challenge.min_required_signatures() as usize,
            )),
        }
    }

    pub fn verify_signatures(
        &self,
        chain_config: &ChainConfig,
    ) -> Result<SigsVerifyResult, PartiallySignedMultisigStructureError> {
        self.check_structurally_valid(chain_config)?;

        if self.signatures.is_empty() {
            return Ok(SigsVerifyResult::Incomplete);
        }

        let verification_result = self.signatures.iter().all(|(index, signature)| {
            let public_key = &self.challenge.public_keys()[index as usize];
            public_key.verify_message(signature, self.message)
        });

        if self.signatures().available_signatures_count()
            < self.challenge.min_required_signatures() as usize
        {
            return Ok(SigsVerifyResult::Incomplete);
        }

        match verification_result {
            false => Ok(SigsVerifyResult::Invalid),
            true => Ok(SigsVerifyResult::CompleteAndValid),
        }
    }
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum PartiallySignedMultisigStructureError {
    #[error("Too many signatures have been added to the challenge: {0} > {1}")]
    Overconstrained(usize, usize),
    #[error("The challenge is structurally invalid and can never be used for signing: {0}")]
    InvalidChallenge(#[from] ClassicMultisigChallengeError),
    #[error("The challenge contains a signature for a public key that does not exist")]
    InvalidSignatureIndex,
}

pub enum PartiallySignedMultisigState {
    /// Not enough signatures have been added to the challenge.
    Incomplete(usize, usize),
    /// Enough signatures have been added to the challenge.
    Complete(usize),
}

#[must_use]
pub enum SigsVerifyResult {
    /// The challenge is structurally valid, and all signatures have been added.
    CompleteAndValid,
    /// The challenge is structurally valid, but not all signatures have been added.
    Incomplete,
    /// The challenge is structurally invalid but the signatures are invalid.
    Invalid,
}
