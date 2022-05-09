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

use crate::primitives::{
    id::{hash_encoded_to, DefaultHashAlgoStream},
    H256,
};

use self::inputsig::StandardInputSignature;

use super::{Destination, Transaction};

pub mod inputsig;
pub mod sighashtype;

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum TransactionSigError {
    #[error("Invalid sighash value provided")]
    InvalidSigHashValue(u8),
    #[error("Invalid input index was provided (provided: `{0}` vs available: `{1}`")]
    InvalidInputIndex(usize, usize),
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
    #[error("Unsupported yet!")]
    Unsupported,
}

pub fn signature_hash(
    mode: sighashtype::SigHashType,
    tx: &Transaction,
    input_num: usize,
) -> Result<H256, TransactionSigError> {
    let mut stream = DefaultHashAlgoStream::new();

    // TODO: even though this works fine, we need to make this function
    // pull the inputs/outputs automatically through macros;
    // the current way is not safe and may produce issues in the future

    let target_input = tx
        .get_inputs()
        .get(input_num)
        .ok_or_else(|| TransactionSigError::InvalidInputIndex(input_num, tx.get_inputs().len()))?;

    hash_encoded_to(&tx.get_flags(), &mut stream);

    match mode.inputs_mode() {
        sighashtype::InputsMode::CommitWhoPays => {
            for input in tx.get_inputs() {
                hash_encoded_to(&input.get_outpoint(), &mut stream);
            }
        }
        sighashtype::InputsMode::AnyoneCanPay => {
            hash_encoded_to(&target_input.get_outpoint(), &mut stream);
        }
    }

    match mode.outputs_mode() {
        sighashtype::OutputsMode::All => {
            hash_encoded_to(tx.get_outputs(), &mut stream);
        }
        sighashtype::OutputsMode::None => (),
        sighashtype::OutputsMode::Single => {
            let output = tx.get_outputs().get(input_num).ok_or_else(|| {
                TransactionSigError::InvalidInputIndex(input_num, tx.get_outputs().len())
            })?;
            hash_encoded_to(&output.encode(), &mut stream);
        }
    }

    hash_encoded_to(&tx.get_lock_time(), &mut stream);

    let result = stream.finalize().into();
    Ok(result)
}

fn verify_standard_input_signature(
    outpoint_destination: &Destination,
    witness: &StandardInputSignature,
    tx: &Transaction,
    input_num: usize,
) -> Result<(), TransactionSigError> {
    let sighash = signature_hash(witness.sighash_type(), tx, input_num)?;
    witness.verify_signature(outpoint_destination, &sighash)?;
    Ok(())
}

pub fn verify_signature(
    outpoint_destination: &Destination,
    tx: &Transaction,
    input_num: usize,
) -> Result<(), TransactionSigError> {
    let target_input = tx
        .get_inputs()
        .get(input_num)
        .ok_or_else(|| TransactionSigError::InvalidInputIndex(input_num, tx.get_inputs().len()))?;
    let input_witness = target_input.get_witness();
    match input_witness {
        inputsig::InputWitness::NoSignature(_) => {
            return Err(TransactionSigError::SignatureNotFound)
        }
        inputsig::InputWitness::Standard(witness) => {
            verify_standard_input_signature(outpoint_destination, witness, tx, input_num)?
        }
    }
    Ok(())
}
// TODO: write tests

#[cfg(test)]
mod test {
    #[test]
    #[allow(clippy::eq_op)]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
