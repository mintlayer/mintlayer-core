// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): S. Afach & L. Kuklinek

use crypto::hash::StreamHasher;
use parity_scale_codec::Encode;

use crate::{
    chain::TxInput,
    primitives::{
        id::{hash_encoded_to, DefaultHashAlgoStream},
        H256,
    },
};

use self::inputsig::StandardInputSignature;

use super::{Destination, Transaction, TxOutput};

pub mod inputsig;
pub mod sighashtype;

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum TransactionSigError {
    #[error("Invalid sighash value provided")]
    InvalidSigHashValue(u8),
    #[error("Invalid input index was provided (provided: `{0}` vs available: `{1}`")]
    InvalidInputIndex(usize, usize),
    #[error("Requested signature hash without the presence of any inputs")]
    SigHashRequestWithoutInputs,
    #[error("Attempted to verify signatures for a transaction without inputs")]
    SignatureVerificationWithoutInputs,
    #[error("Input corresponding to output number {0} does not exist (number of inputs is {1})")]
    InvalidOutputIndexForModeSingle(usize, usize),
    #[error("Decoding witness failed ")]
    DecodingWitnessFailed,
    #[error("Signature verification failed ")]
    SignatureVerificationFailed,
    #[error("Public key to address mismatch")]
    PublicKeyToAddressMismatch,
    #[error("Address authorization decoding failed")]
    AddressAuthDecodingFailed(String),
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
    #[error("Unsupported yet!")]
    Unsupported,
}

pub fn signature_hash_for_inputs(
    stream: &mut DefaultHashAlgoStream,
    mode: sighashtype::SigHashType,
    inputs: &[TxInput],
    target_input: &TxInput,
) {
    match mode.inputs_mode() {
        sighashtype::InputsMode::CommitWhoPays => {
            hash_encoded_to(&(inputs.len() as u32), stream);
            for input in inputs {
                hash_encoded_to(&input.get_outpoint(), stream);
            }
        }
        sighashtype::InputsMode::AnyoneCanPay => {
            hash_encoded_to(&target_input.get_outpoint(), stream);
        }
    }
}

pub fn signature_hash_for_outputs(
    stream: &mut DefaultHashAlgoStream,
    mode: sighashtype::SigHashType,
    outputs: &[TxOutput],
    target_input_num: usize,
) -> Result<(), TransactionSigError> {
    match mode.outputs_mode() {
        sighashtype::OutputsMode::All => {
            hash_encoded_to(&outputs, stream);
        }
        sighashtype::OutputsMode::None => (),
        sighashtype::OutputsMode::Single => {
            let output = outputs.get(target_input_num).ok_or({
                TransactionSigError::InvalidInputIndex(target_input_num, outputs.len())
            })?;
            hash_encoded_to(&output, stream);
        }
    }
    Ok(())
}

trait SignatureHashableElement {
    fn signature_hash(
        &self,
        stream: &mut DefaultHashAlgoStream,
        mode: sighashtype::SigHashType,
        target_input: &TxInput,
        target_input_num: usize,
    ) -> Result<(), TransactionSigError>;
}

impl SignatureHashableElement for &[TxInput] {
    fn signature_hash(
        &self,
        stream: &mut DefaultHashAlgoStream,
        mode: sighashtype::SigHashType,
        target_input: &TxInput,
        _target_input_num: usize,
    ) -> Result<(), TransactionSigError> {
        match mode.inputs_mode() {
            sighashtype::InputsMode::CommitWhoPays => {
                hash_encoded_to(&(self.len() as u32), stream);
                for input in *self {
                    hash_encoded_to(&input.get_outpoint(), stream);
                }
            }
            sighashtype::InputsMode::AnyoneCanPay => {
                hash_encoded_to(&target_input.get_outpoint(), stream);
            }
        }
        Ok(())
    }
}

impl SignatureHashableElement for &[TxOutput] {
    fn signature_hash(
        &self,
        stream: &mut DefaultHashAlgoStream,
        mode: sighashtype::SigHashType,
        _target_input: &TxInput,
        target_input_num: usize,
    ) -> Result<(), TransactionSigError> {
        match mode.outputs_mode() {
            sighashtype::OutputsMode::All => {
                hash_encoded_to(self, stream);
            }
            sighashtype::OutputsMode::None => (),
            sighashtype::OutputsMode::Single => {
                let output = self.get(target_input_num).ok_or({
                    TransactionSigError::InvalidInputIndex(target_input_num, self.len())
                })?;
                hash_encoded_to(&output, stream);
            }
        }
        Ok(())
    }
}

fn hash_encoded_if_some<T: Encode>(val: &Option<T>, stream: &mut DefaultHashAlgoStream) {
    match val {
        Some(ref v) => hash_encoded_to(&v, stream),
        None => (),
    }
}

pub trait Transactable {
    fn inputs(&self) -> Option<&[TxInput]>;
    fn outputs(&self) -> Option<&[TxOutput]>;
    fn version_byte(&self) -> Option<u8>;
    fn lock_time(&self) -> Option<u32>;
    fn flags(&self) -> Option<u32>;
}

impl Transactable for Transaction {
    fn inputs(&self) -> Option<&[TxInput]> {
        Some(self.get_inputs())
    }

    fn outputs(&self) -> Option<&[TxOutput]> {
        Some(self.get_outputs())
    }

    fn version_byte(&self) -> Option<u8> {
        Some(self.version_byte())
    }

    fn lock_time(&self) -> Option<u32> {
        Some(self.get_lock_time())
    }

    fn flags(&self) -> Option<u32> {
        Some(self.get_flags())
    }
}

fn stream_signature_hash<T: Transactable>(
    tx: &T,
    stream: &mut DefaultHashAlgoStream,
    mode: sighashtype::SigHashType,
    target_input_num: usize,
) -> Result<(), TransactionSigError> {
    // TODO: even though this works fine, we need to make this function
    // pull the inputs/outputs automatically through macros;
    // the current way is not safe and may produce issues in the future

    let inputs = match tx.inputs() {
        Some(ins) => ins,
        None => return Err(TransactionSigError::SigHashRequestWithoutInputs),
    };

    let outputs = tx.outputs().unwrap_or_default();

    let target_input = inputs.get(target_input_num).ok_or(
        TransactionSigError::InvalidInputIndex(target_input_num, inputs.len()),
    )?;

    hash_encoded_to(&mode.get(), stream);

    hash_encoded_if_some(&tx.version_byte(), stream);
    hash_encoded_if_some(&tx.flags(), stream);
    hash_encoded_if_some(&tx.lock_time(), stream);

    inputs.signature_hash(stream, mode, target_input, target_input_num)?;
    outputs.signature_hash(stream, mode, target_input, target_input_num)?;

    // TODO: consider doing just like taproot, and hash in all outputs that come from the outpoints of inputs,
    //       this would be a good solution to avoid having to download full trasactions to verify inputs

    // TODO: for P2SH add OP_CODESEPARATOR position
    hash_encoded_to(&u32::MAX, stream);

    Ok(())
}

pub fn signature_hash<T: Transactable>(
    mode: sighashtype::SigHashType,
    tx: &T,
    input_num: usize,
) -> Result<H256, TransactionSigError> {
    let mut stream = DefaultHashAlgoStream::new();

    stream_signature_hash(tx, &mut stream, mode, input_num)?;

    let result = stream.finalize().into();
    Ok(result)
}

fn verify_standard_input_signature<T: Transactable>(
    outpoint_destination: &Destination,
    witness: &StandardInputSignature,
    tx: &T,
    input_num: usize,
) -> Result<(), TransactionSigError> {
    let sighash = signature_hash(witness.sighash_type(), tx, input_num)?;
    witness.verify_signature(outpoint_destination, &sighash)?;
    Ok(())
}

pub fn verify_signature<T: Transactable>(
    outpoint_destination: &Destination,
    tx: &T,
    input_num: usize,
) -> Result<(), TransactionSigError> {
    let inputs = tx.inputs().ok_or(TransactionSigError::SignatureVerificationWithoutInputs)?;
    let target_input = inputs.get(input_num).ok_or(TransactionSigError::InvalidInputIndex(
        input_num,
        inputs.len(),
    ))?;
    let input_witness = target_input.get_witness();
    match input_witness {
        inputsig::InputWitness::NoSignature(_) => match outpoint_destination {
            Destination::Address(_) | Destination::PublicKey(_) | Destination::ScriptHash(_) => {
                return Err(TransactionSigError::SignatureNotFound)
            }
            Destination::AnyoneCanSpend => {}
        },
        inputsig::InputWitness::Standard(witness) => {
            verify_standard_input_signature(outpoint_destination, witness, tx, input_num)?
        }
    }
    Ok(())
}
