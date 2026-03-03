// Copyright (c) 2021-2026 RBB S.r.l
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

use crate::signer::{DestinationSigError, SignatureStatus, SignerError, SignerResult};

use common::{
    chain::{
        signature::inputsig::{
            arbitrary_message::ArbitraryMessageSignature,
            authorize_pubkey_spend::AuthorizedPublicKeySpend,
            authorize_pubkeyhash_spend::AuthorizedPublicKeyHashSpend,
            classical_multisig::authorize_classical_multisig::{
                sign_classical_multisig_spending, AuthorizedClassicalMultisigSpend,
                ClassicalMultisigCompletionStatus,
            },
        },
        ChainConfig, DestinationTag,
    },
    primitives::H256,
};
use crypto::key::{
    extended::ExtendedPublicKey, signature::SignatureKind, PrivateKey, SigAuxDataProvider,
    Signature, SignatureError,
};
use serialization::Encode;

/// Hardware Signer errors
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum HardwareSignerError {
    #[error("Missing multisig index for signature returned from Device")]
    MissingMultisigIndexForSignature,
    #[error("Signature construction error: {0}")]
    SignatureError(#[from] SignatureError),
}

pub struct StandaloneInput {
    pub multisig_idx: Option<u32>,
    pub private_key: PrivateKey,
}

pub type StandaloneInputs = BTreeMap</*input index*/ u32, Vec<StandaloneInput>>;

pub fn sign_with_standalone_private_keys(
    chain_config: &ChainConfig,
    sig_aux_data_provider: &mut (impl SigAuxDataProvider + ?Sized),
    current_signatures: AuthorizedClassicalMultisigSpend,
    standalone_inputs: &[StandaloneInput],
    new_status: SignatureStatus,
    sighash: H256,
) -> SignerResult<(AuthorizedClassicalMultisigSpend, SignatureStatus)> {
    let challenge = current_signatures.challenge().clone();

    standalone_inputs.iter().try_fold(
        (current_signatures, new_status),
        |(mut current_signatures, mut status), inp| -> SignerResult<_> {
            if status == SignatureStatus::FullySigned {
                return Ok((current_signatures, status));
            }

            let key_index =
                inp.multisig_idx.ok_or(HardwareSignerError::MissingMultisigIndexForSignature)?;
            let res = sign_classical_multisig_spending(
                chain_config,
                key_index as u8,
                &inp.private_key,
                &challenge,
                &sighash,
                current_signatures,
                sig_aux_data_provider,
            )
            .map_err(DestinationSigError::ClassicalMultisigSigningFailed)?;

            match res {
                ClassicalMultisigCompletionStatus::Complete(signatures) => {
                    current_signatures = signatures;
                    status = SignatureStatus::FullySigned;
                }
                ClassicalMultisigCompletionStatus::Incomplete(signatures) => {
                    current_signatures = signatures;
                    status = SignatureStatus::PartialMultisig {
                        required_signatures: challenge.min_required_signatures(),
                        num_signatures: current_signatures.signatures().len() as u8,
                    };
                }
            };

            Ok((current_signatures, status))
        },
    )
}

pub fn arbitrary_message_signature_from_raw_sig(
    raw_sig: &[u8],
    destination: DestinationTag,
    xpub: ExtendedPublicKey,
) -> SignerResult<ArbitraryMessageSignature> {
    let signature = Signature::from_raw_data(raw_sig, SignatureKind::Secp256k1Schnorr)
        .map_err(HardwareSignerError::SignatureError)?;

    let data = match &destination {
        DestinationTag::PublicKey => Ok(AuthorizedPublicKeySpend::new(signature).encode()),
        DestinationTag::PublicKeyHash => {
            Ok(AuthorizedPublicKeyHashSpend::new(xpub.into_public_key(), signature)
                .encode())
        }
        DestinationTag::AnyoneCanSpend => {
            Err(SignerError::SigningError(
                DestinationSigError::AttemptedToProduceSignatureForAnyoneCanSpend,
            ))
        }
        DestinationTag::ClassicMultisig => {
            Err(SignerError::SigningError(
                DestinationSigError::AttemptedToProduceClassicalMultisigSignatureInUnipartySignatureCode,
            ))
        }
        DestinationTag::ScriptHash => {
            Err(SignerError::SigningError(
                DestinationSigError::Unsupported,
            ))
        }
    }?;

    let sig = ArbitraryMessageSignature::from_data(data);
    Ok(sig)
}
