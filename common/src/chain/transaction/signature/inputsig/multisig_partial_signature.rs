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

use crate::chain::{
    classic_multisig::{ClassicMultisigChallenge, ClassicMultisigChallengeError},
    ChainConfig,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartiallySignedMultisigChallenge {
    /// The signatures that have been added to this challenge. The indices are the indices of the public keys.
    signatures: BTreeMap<u32, Signature>,
    message: Vec<u8>,
    /// The challenge that is being signed.
    challenge: ClassicMultisigChallenge,
}

impl PartiallySignedMultisigChallenge {
    pub fn from_challenge(challenge: ClassicMultisigChallenge, message: Vec<u8>) -> Self {
        PartiallySignedMultisigChallenge {
            signatures: BTreeMap::new(),
            challenge,
            message,
        }
    }

    pub fn take_signatures(self) -> BTreeMap<u32, Signature> {
        self.signatures
    }

    pub fn add_signature(&mut self, index: u32, signature: Signature) {
        self.signatures.insert(index, signature);
    }

    pub fn signatures(&self) -> &BTreeMap<u32, Signature> {
        &self.signatures
    }

    pub fn missing_signatures_count(&self) -> i32 {
        self.challenge.min_required_signatures().get() as i32 - self.signatures.len() as i32
    }

    /// Check whether the structure of the multisig challenge and signatures is valid, but without validating signatures
    pub fn is_structurally_valid(
        &self,
        chain_config: &ChainConfig,
    ) -> PartiallySignedMultisigState {
        if let Err(err) = self.challenge.is_valid(chain_config) {
            return PartiallySignedMultisigState::InvalidChallenge(err);
        }

        if self
            .signatures
            .keys()
            .any(|index| *index as usize >= self.challenge.public_keys().len())
        {
            return PartiallySignedMultisigState::InvalidSignatureIndex;
        }

        let missing_signatures_count = self.missing_signatures_count();
        match missing_signatures_count.cmp(&0) {
            std::cmp::Ordering::Less => PartiallySignedMultisigState::Overconstrained(
                self.signatures.len(),
                self.challenge.min_required_signatures().get() as usize,
            ),
            std::cmp::Ordering::Equal => {
                PartiallySignedMultisigState::Complete(self.signatures.len())
            }
            std::cmp::Ordering::Greater => PartiallySignedMultisigState::Incomplete(
                self.signatures.len(),
                self.challenge.min_required_signatures().get() as usize,
            ),
        }
    }

    pub fn validate_signatures(&self, chain_config: &ChainConfig) -> Option<bool> {
        if !self.is_structurally_valid(chain_config).is_valid_for_signing() {
            return None;
        }

        let validation_status = self.signatures.iter().all(|(index, signature)| {
            let public_key = &self.challenge.public_keys()[*index as usize];
            public_key.verify_message(signature, &self.message)
        });

        Some(validation_status)
    }
}

#[must_use]
pub enum PartiallySignedMultisigState {
    /// Not enough signatures have been added to the challenge.
    Incomplete(usize, usize),
    /// Enough signatures have been added to the challenge.
    Complete(usize),
    /// Too many signatures have been added to the challenge.
    Overconstrained(usize, usize),
    /// The challenge is structurally invalid and can never be used.
    InvalidChallenge(ClassicMultisigChallengeError),
    /// The challenge contains a signature for a public key that does not exist.
    InvalidSignatureIndex,
}

impl PartiallySignedMultisigState {
    pub fn is_valid_for_signing(&self) -> bool {
        match self {
            PartiallySignedMultisigState::Incomplete(_, _) => true,
            PartiallySignedMultisigState::Complete(_) => true,
            PartiallySignedMultisigState::Overconstrained(_, _) => false,
            PartiallySignedMultisigState::InvalidChallenge(_) => false,
            PartiallySignedMultisigState::InvalidSignatureIndex => false,
        }
    }
}
