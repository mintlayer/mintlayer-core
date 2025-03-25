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
use serialization::Encode;

mod hashable;
pub mod sighashtype;

use crate::{
    chain::{OrderData, PoolData, TxOutput},
    primitives::{
        id::{hash_encoded_to, DefaultHashAlgoStream},
        Amount, H256,
    },
};

use self::hashable::{SignatureHashableElement, SignatureHashableInputs};

use super::{DestinationSigError, Signable};

// FIXME: document
#[derive(Clone, Debug, Encode)]
pub enum InputInfo<'a> {
    #[codec(index = 0)]
    None,
    #[codec(index = 1)]
    Utxo(&'a TxOutput),
    #[codec(index = 2)]
    Order {
        data: &'a OrderData,
        ask_balance: Amount,
        give_balance: Amount,
    },
    #[codec(index = 3)]
    Pool(&'a PoolData),
}

fn hash_encoded_if_some<T: Encode>(val: &Option<T>, stream: &mut DefaultHashAlgoStream) {
    if let Some(v) = val {
        hash_encoded_to(&v, stream)
    }
}

fn stream_signature_hash<T: Signable>(
    tx: &T,
    inputs_info: &[InputInfo],
    stream: &mut DefaultHashAlgoStream,
    mode: sighashtype::SigHashType,
    target_input_index: usize,
) -> Result<(), DestinationSigError> {
    let inputs = tx.inputs().ok_or(DestinationSigError::SigHashRequestWithoutInputs)?;

    let target_input = inputs.get(target_input_index).ok_or(
        DestinationSigError::InvalidInputIndex(target_input_index, inputs.len()),
    )?;

    hash_encoded_to(&mode.get(), stream);

    hash_encoded_if_some(&tx.version_byte(), stream);
    hash_encoded_if_some(&tx.flags(), stream);

    let inputs_hashable = SignatureHashableInputs::new(inputs, inputs_info)?;
    inputs_hashable.signature_hash(stream, mode, target_input, target_input_index)?;

    let outputs_hashable = tx.outputs().unwrap_or_default();
    outputs_hashable.signature_hash(stream, mode, target_input, target_input_index)?;

    Ok(())
}

pub fn signature_hash<T: Signable>(
    mode: sighashtype::SigHashType,
    tx: &T,
    inputs_info: &[InputInfo],
    input_index: usize,
) -> Result<H256, DestinationSigError> {
    let mut stream = DefaultHashAlgoStream::new();

    stream_signature_hash(tx, inputs_info, &mut stream, mode, input_index)?;

    let result = stream.finalize().into();
    Ok(result)
}
