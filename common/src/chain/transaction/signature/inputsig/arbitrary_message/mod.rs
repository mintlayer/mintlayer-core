// Copyright (c) 2021-2024 RBB S.r.l
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

const MESSAGE_MAGIC_PREFIX: &str = "===MINTLAYER MESSAGE BEGIN===\n";
const MESSAGE_MAGIC_SUFFIX: &str = "\n===MINTLAYER MESSAGE END===";

use thiserror::Error;

use crypto::key::SigAuxDataProvider;
use serialization::Encode;

use crate::{
    chain::{signature::DestinationSigError, ChainConfig, Destination},
    primitives::{id::default_hash, H256},
};

use super::{
    authorize_pubkey_spend::{
        sign_public_key_spending, verify_public_key_spending, AuthorizedPublicKeySpend,
    },
    authorize_pubkeyhash_spend::{
        sign_public_key_hash_spending, sign_public_key_hash_spending_unchecked,
        verify_public_key_hash_spending, AuthorizedPublicKeyHashSpend,
    },
    classical_multisig::authorize_classical_multisig::{
        verify_classical_multisig_spending, AuthorizedClassicalMultisigSpend,
    },
};

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SignArbitraryMessageError {
    #[error("Destination signature error: {0}")]
    DestinationSigError(#[from] DestinationSigError),
    #[error("AnyoneCanSpend should not use standard signatures, so producing a signature for it is not possible")]
    AttemptedToProduceSignatureForAnyoneCanSpend,
    #[error("Classical multisig signature attempted in uni-party function")]
    AttemptedToProduceClassicalMultisigSignatureInUnipartySignatureCode,
    #[error("Unsupported yet!")]
    Unsupported,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ArbitraryMessageSignature {
    raw_signature: Vec<u8>,
}

pub fn produce_message_challenge(message: &[u8]) -> H256 {
    let wrapped_message = MESSAGE_MAGIC_PREFIX
        .as_bytes()
        .iter()
        .chain(message.iter())
        .chain(MESSAGE_MAGIC_SUFFIX.as_bytes().iter())
        .copied()
        .collect::<Vec<_>>();

    // Hash it. Now it's impossible to make this useful for a transaction
    default_hash(wrapped_message)
}

impl ArbitraryMessageSignature {
    pub fn from_data(raw_signature: Vec<u8>) -> Self {
        Self { raw_signature }
    }

    pub fn to_hex(&self) -> String {
        self.as_ref().to_hex()
    }

    pub fn as_raw(&self) -> &[u8] {
        &self.raw_signature
    }

    pub fn into_raw(self) -> Vec<u8> {
        self.raw_signature
    }

    pub fn as_ref(&self) -> ArbitraryMessageSignatureRef<'_> {
        ArbitraryMessageSignatureRef::from_data(&self.raw_signature)
    }

    pub fn verify_signature(
        &self,
        chain_config: &ChainConfig,
        destination: &Destination,
        challenge: &H256,
    ) -> Result<(), DestinationSigError> {
        self.as_ref().verify_signature(chain_config, destination, challenge)
    }

    pub fn produce_uniparty_signature<AuxP: SigAuxDataProvider + ?Sized>(
        private_key: &crypto::key::PrivateKey,
        destination: &Destination,
        message: &[u8],
        sig_aux_data_provider: &mut AuxP,
    ) -> Result<Self, SignArbitraryMessageError> {
        let challenge = produce_message_challenge(message);
        let signature =
            match destination {
                Destination::PublicKeyHash(pubkeyhash) => {
                    let sig = sign_public_key_hash_spending(private_key, pubkeyhash, &challenge, sig_aux_data_provider)?;
                    sig.encode()
                }
                Destination::PublicKey(pubkey) => {
                    let sig = sign_public_key_spending(private_key, pubkey, &challenge, sig_aux_data_provider)?;
                    sig.encode()
                }
                Destination::ScriptHash(_) => return Err(SignArbitraryMessageError::Unsupported),

                Destination::AnyoneCanSpend => {
                    // AnyoneCanSpend makes no sense for signing and verification.
                    return Err(SignArbitraryMessageError::AttemptedToProduceSignatureForAnyoneCanSpend);
                }
                Destination::ClassicMultisig(_) => return Err(
                    // This function doesn't support this kind of signature
                    SignArbitraryMessageError::AttemptedToProduceClassicalMultisigSignatureInUnipartySignatureCode,
                ),
            };
        Ok(Self {
            raw_signature: signature,
        })
    }

    pub fn produce_uniparty_signature_as_pub_key_hash_spending<
        AuxP: SigAuxDataProvider + ?Sized,
    >(
        private_key: &crypto::key::PrivateKey,
        message: &[u8],
        sig_aux_data_provider: &mut AuxP,
    ) -> Result<Self, SignArbitraryMessageError> {
        let challenge = produce_message_challenge(message);
        let signature = sign_public_key_hash_spending_unchecked(
            private_key,
            &challenge,
            sig_aux_data_provider,
        )?;
        let signature = signature.encode();

        Ok(Self {
            raw_signature: signature,
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ArbitraryMessageSignatureRef<'a> {
    raw_signature: &'a [u8],
}

impl<'a> ArbitraryMessageSignatureRef<'a> {
    pub fn from_data(raw_signature: &'a [u8]) -> Self {
        Self { raw_signature }
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.raw_signature)
    }

    pub fn as_raw(&self) -> &[u8] {
        self.raw_signature
    }

    pub fn verify_signature(
        &self,
        chain_config: &ChainConfig,
        destination: &Destination,
        challenge: &H256,
    ) -> Result<(), DestinationSigError> {
        match destination {
            Destination::PublicKeyHash(addr) => {
                let sig_components = AuthorizedPublicKeyHashSpend::from_data(self.raw_signature)?;
                verify_public_key_hash_spending(addr, &sig_components, challenge)?
            }
            Destination::PublicKey(pubkey) => {
                let sig_components = AuthorizedPublicKeySpend::from_data(self.raw_signature)?;
                verify_public_key_spending(pubkey, &sig_components, challenge)?
            }
            Destination::ScriptHash(_) => return Err(DestinationSigError::Unsupported),
            Destination::AnyoneCanSpend => {
                // AnyoneCanSpend makes no sense for signing and verification.
                return Err(
                    DestinationSigError::AttemptedToVerifyStandardSignatureForAnyoneCanSpend,
                );
            }
            Destination::ClassicMultisig(h) => {
                let sig_components =
                    AuthorizedClassicalMultisigSpend::from_data(self.raw_signature)?;
                verify_classical_multisig_spending(chain_config, h, &sig_components, challenge)?
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
