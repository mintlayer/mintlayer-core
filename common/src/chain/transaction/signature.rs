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
    address::AddressError,
    chain::ChainConfig,
    primitives::{id::DefaultHashAlgoStream, H256},
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
    #[error("OutputsMode::Single with more inputs than outputs (`{0}` vs available: `{1}`)")]
    InvalidOutputIndexForModeSingle(usize, usize),
    #[error("Decoding witness failed ")]
    DecodingWitnessFailed,
    #[error("Signature verification failed ")]
    SignatureVerificationFailed,
    #[error("Public key to address mismatch")]
    PublicKeyToAddressMismatch,
    #[error("Address authorization decoding failed")]
    AddressAuthDecodingFailed(String),
    #[error("Public key to address conversion failed")]
    PublicKeyToAddressConversionFailed(AddressError),
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

    stream.write(tx.get_flags().encode());

    match mode.inputs_mode() {
        sighashtype::InputsMode::CommitWhoPays => {
            for input in tx.get_inputs() {
                let encoded = input.get_outpoint().encode();
                stream.write(encoded);
            }
        }
        sighashtype::InputsMode::AnyoneCanPay => {
            let encoded = target_input.get_outpoint().encode();
            stream.write(encoded);
        }
    }

    match mode.outputs_mode() {
        sighashtype::OutputsMode::All => {
            for output in tx.get_outputs() {
                let encoded = output.encode();
                stream.write(encoded);
            }
        }
        sighashtype::OutputsMode::None => (),
        sighashtype::OutputsMode::Single => {
            let output = tx.get_outputs().get(input_num).ok_or_else(|| {
                TransactionSigError::InvalidInputIndex(input_num, tx.get_outputs().len())
            })?;
            let encoded = output.encode();
            stream.write(encoded);
        }
    }

    stream.write(tx.get_lock_time().encode());

    let result = stream.finalize().into();
    Ok(result)
}

fn verify_standard_input_signature(
    chain_config: &ChainConfig,
    outpoint_destination: &Destination,
    witness: &StandardInputSignature,
    tx: &Transaction,
    input_num: usize,
) -> Result<(), TransactionSigError> {
    let sighash = signature_hash(witness.get_sighash_type(), tx, input_num)?;
    witness.verify_signature(chain_config, outpoint_destination, &sighash)?;
    Ok(())
}

pub fn verify_signature(
    chain_config: &ChainConfig,
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
        inputsig::InputWitness::Standard(witness) => verify_standard_input_signature(
            chain_config,
            outpoint_destination,
            witness,
            tx,
            input_num,
        )?,
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
