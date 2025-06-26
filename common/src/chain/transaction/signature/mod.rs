// Copyright (c) 2021-2022 RBB S.r.l
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

use thiserror::Error;

use serialization::{Decode, Encode};
use utils::ensure;

use crate::chain::{ChainConfig, TxInput};

use super::{Destination, TxOutput};

use self::{
    inputsig::{
        classical_multisig::{
            authorize_classical_multisig::ClassicalMultisigSigningError,
            multisig_partial_signature::PartiallySignedMultisigStructureError,
        },
        standard_signature::StandardInputSignature,
        InputWitness,
    },
    sighash::{input_commitments::SighashInputCommitment, signature_hash},
};

pub mod inputsig;
pub mod sighash;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum DestinationSigError {
    #[error("Invalid sighash value provided")]
    InvalidSigHashValue(u8),
    #[error("Invalid input index was provided (provided: `{0}` vs available: `{1}`)")]
    InvalidInputIndex(usize, usize),
    #[error("Input commitments count {0} does not match inputs count {1}")]
    InvalidInputCommitmentsCountVsInputs(usize, usize),
    #[error("Invalid signature index was provided (provided: `{0}` vs available: `{1}`)")]
    InvalidSignatureIndex(usize, usize),
    #[error("Requested signature hash without the presence of any inputs")]
    SigHashRequestWithoutInputs,
    #[error("Attempted to verify signatures for a transaction without inputs")]
    SignatureVerificationWithoutInputs,
    #[error("Attempted to verify signatures for a transaction without signatures")]
    SignatureVerificationWithoutSigs,
    #[error("Input corresponding to output number {0} does not exist (number of inputs is {1})")]
    InvalidOutputIndexForModeSingle(usize, usize),
    #[error("Decoding witness failed")]
    DecodingWitnessFailed,
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    #[error("Public key to public key hash mismatch")]
    PublicKeyToHashMismatch,
    #[error("Address authorization decoding failed: {0}")]
    AddressAuthDecodingFailed(serialization::Error),
    #[error("Signature decoding failed")]
    InvalidSignatureEncoding,
    #[error("No signature!")]
    SignatureNotFound,
    #[error("Producing signature failed!")]
    ProducingSignatureFailed(crypto::key::SignatureError),
    #[error("Private key does not match with spender public key")]
    SpendeePrivatePublicKeyMismatch,
    #[error("AnyoneCanSpend should not use standard signatures, this place should be unreachable")]
    AttemptedToVerifyStandardSignatureForAnyoneCanSpend,
    #[error("AnyoneCanSpend should not use standard signatures, so producing a signature for it is not possible")]
    AttemptedToProduceSignatureForAnyoneCanSpend,
    #[error("Classical multisig signature attempted in uni-party function")]
    AttemptedToProduceClassicalMultisigSignatureInUnipartySignatureCode,
    #[error("Number of signatures does not match number of inputs")]
    InvalidWitnessCount,
    #[error("Invalid classical multisig challenge")]
    InvalidClassicalMultisig(#[from] PartiallySignedMultisigStructureError),
    #[error("Incomplete classical multisig , required {0} but have {1} signature(s)")]
    IncompleteClassicalMultisigSignature(u8, u8),
    #[error("Invalid classical multisig signature(s)")]
    InvalidClassicalMultisigSignature,
    #[error("The hash provided does not match the hash in the witness")]
    ClassicalMultisigWitnessHashMismatch,
    #[error("Producing classical multisig signing failed: {0}")]
    ClassicalMultisigSigningFailed(#[from] ClassicalMultisigSigningError),
    #[error("Standard signature creation failed. Invalid classical multisig authorization")]
    InvalidClassicalMultisigAuthorization,
    #[error("Standard signature creation failed. Incomplete classical multisig authorization")]
    IncompleteClassicalMultisigAuthorization,
    #[error("Unsupported yet!")]
    Unsupported,
}

impl From<std::convert::Infallible> for DestinationSigError {
    fn from(value: std::convert::Infallible) -> Self {
        match value {}
    }
}

pub trait Signable {
    fn inputs(&self) -> Option<&[TxInput]>;
    fn outputs(&self) -> Option<&[TxOutput]>;
    fn version_byte(&self) -> Option<u8>;
    fn flags(&self) -> Option<u128>;
}

pub trait Transactable: Signable {
    fn signatures(&self) -> Vec<Option<InputWitness>>;
}

/// `StandardInputSignature` can contain additional data encoded inside raw signature (e.g. htlc info)
/// so it's not possible to verify it without evaluating first.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum EvaluatedInputWitness {
    #[codec(index = 0)]
    NoSignature(Option<Vec<u8>>),
    #[codec(index = 1)]
    Standard(StandardInputSignature),
}

pub fn verify_signature<T: Signable>(
    chain_config: &ChainConfig,
    outpoint_destination: &Destination,
    tx: &T,
    input_witness: &EvaluatedInputWitness,
    input_commitments: &[SighashInputCommitment],
    input_index: usize,
) -> Result<(), DestinationSigError> {
    let inputs = tx.inputs().ok_or(DestinationSigError::SignatureVerificationWithoutInputs)?;
    ensure!(
        input_index < inputs.len(),
        DestinationSigError::InvalidSignatureIndex(input_index, inputs.len(),)
    );

    match input_witness {
        EvaluatedInputWitness::NoSignature(_) => match outpoint_destination {
            Destination::PublicKeyHash(_)
            | Destination::PublicKey(_)
            | Destination::ScriptHash(_)
            | Destination::ClassicMultisig(_) => {
                return Err(DestinationSigError::SignatureNotFound)
            }
            Destination::AnyoneCanSpend => {}
        },
        EvaluatedInputWitness::Standard(witness) => {
            let sighash =
                signature_hash(witness.sighash_type(), tx, input_commitments, input_index)?;
            witness.verify_signature(chain_config, outpoint_destination, &sighash)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
