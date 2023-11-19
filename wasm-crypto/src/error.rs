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

use wasm_bindgen::JsValue;

#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    #[error("Invalid private key encoding")]
    InvalidPrivateKeyEncoding,
    #[error("Signature error: {0}")]
    SignatureError(#[from] crypto::key::SignatureError),
    #[error("Invalid public key encoding")]
    InvalidPublicKeyEncoding,
    #[error("Invalid signature encoding")]
    InvalidSignatureEncoding,
    #[error("Invalid mnemonic string")]
    InvalidMnemonic,
    #[error("Invalid key index, MSB bit set")]
    InvalidKeyIndex,
    #[error("Invalid outpoint ID encoding")]
    InvalidOutpointId,
    #[error("Invalid addressable encoding")]
    InvalidAddressable,
    #[error("Invalid amount")]
    InvalidAmount,
    #[error("Invalid time lock encoding")]
    InvalidTimeLock,
    #[error("Invalid per thousand {0} valid range is [0, 1000]")]
    InvalidPerThousedns(u16),
    #[error("Invalid stake pool data encoding")]
    InvalidStakePoolData,
    #[error("Invalid Transaction output encoding")]
    InvalidOutput,
    #[error("Invalid Transaction input encoding")]
    InvalidInput,
    #[error("Invalid Transaction witness encoding")]
    InvalidWitness,
    #[error("Invalid transaction encoding")]
    InvalidTransaction,
    #[error("The number of signatures does not match the number of inputs")]
    InvalidWitnessCount,
}

// This is required to make an error readable in JavaScript
impl From<Error> for JsValue {
    fn from(value: Error) -> Self {
        JsValue::from_str(&format!("{}", value))
    }
}
