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
