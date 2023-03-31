// Copyright (c) 2023 RBB S.r.l
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

use crypto::hash::StreamHasher;
use parity_scale_codec::Encode;

use crate::{
    chain::{TxInput, TxOutput},
    primitives::{
        id::{hash_encoded_to, DefaultHashAlgoStream},
        H256,
    },
};

use super::{sighashtype, Signable, TransactionSigError};

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
                    hash_encoded_to(&input.outpoint(), stream);
                }
            }
            sighashtype::InputsMode::AnyoneCanPay => {
                hash_encoded_to(&target_input.outpoint(), stream);
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

fn stream_signature_hash<T: Signable>(
    tx: &T,
    inputs_utxos: &[&TxOutput],
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

    // Include utxos of the inputs to make it possible to verify the inputs scripts and amounts without downloading the full transactions
    if inputs.len() != inputs_utxos.len() {
        return Err(TransactionSigError::InvalidUtxoCountVsInputs(
            inputs_utxos.len(),
            inputs.len(),
        ));
    } else {
        hash_encoded_to(&inputs_utxos, stream);
    }

    // TODO: for P2SH add OP_CODESEPARATOR position
    hash_encoded_to(&u32::MAX, stream);

    Ok(())
}

pub fn signature_hash<T: Signable>(
    mode: sighashtype::SigHashType,
    tx: &T,
    inputs_utxos: &[&TxOutput],
    input_num: usize,
) -> Result<H256, TransactionSigError> {
    let mut stream = DefaultHashAlgoStream::new();

    stream_signature_hash(tx, inputs_utxos, &mut stream, mode, input_num)?;

    let result = stream.finalize().into();
    Ok(result)
}
