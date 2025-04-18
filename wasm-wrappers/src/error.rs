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

use common::chain::{
    signature::{inputsig::arbitrary_message::SignArbitraryMessageError, DestinationSigError},
    IdCreationError, SignedTransactionIntentError, TransactionCreationError,
};
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
    #[error("Invalid addressable: {addressable}")]
    InvalidAddressable { addressable: String },
    #[error("Transaction size estimation error: {error}")]
    TransactionSizeEstimationError { error: String },
    #[error("NFT Creator needs to be a public key address")]
    InvalidCreatorPublicKey,
    #[error("Invalid amount")]
    InvalidAmount,
    #[error("Invalid time lock encoding")]
    InvalidTimeLock,
    #[error("Invalid per thousand {0} valid range is [0, 1000]")]
    InvalidPerThousand(u16),
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
    #[error("Invalid transaction id encoding")]
    InvalidTransactionId,
    #[error("The number of signatures does not match the number of inputs")]
    InvalidWitnessCount,
    #[error("Invalid htlc secret encoding")]
    InvalidHtlcSecret,
    #[error("Invalid htlc secret hash encoding")]
    InvalidHtlcSecretHash,
    #[error("Invalid signed transaction intent encoding")]
    InvalidSignedTransactionIntent,
    #[error("No input outpoint found in transaction")]
    NoInputOutpointFound,
    #[error("Invalid multisig challenge encoding")]
    InvalidMultisigChallenge,
    #[error("Multisig required signatures cannot be zero")]
    ZeroMultisigRequiredSigs,
    #[error("Final supply calculation error")]
    FinalSupplyError,
    #[error("Calculating effective balance failed: {0}")]
    EffectiveBalanceCalculationFailed(String),
    #[error("When fixed total supply is selected an amount must be present as well")]
    FixedTotalSupply,
    #[error("Invalid token parameters: {0}")]
    TokenIssuanceError(#[from] tx_verifier::error::TokenIssuanceError),
    #[error("Transaction creation error: {0}")]
    TransactionCreationError(#[from] TransactionCreationError),
    #[error("Signature error: {0}")]
    DestinationSigError(#[from] DestinationSigError),
    #[error("Id creation error: {0}")]
    IdCreationError(#[from] IdCreationError),
    #[error("Invalid message signature encoding")]
    InvalidMessageSignature,
    #[error("Arbitrary message signing error: {0}")]
    SignArbitraryMessageError(#[from] SignArbitraryMessageError),
    #[error("Error decoding a JsValue as an array of arrays of bytes: {error}")]
    JsValueNotArrayOfArraysOfBytes { error: String },
    #[error("Signed transaction intent error: {0}")]
    SignedTransactionIntentError(#[from] SignedTransactionIntentError),
    #[error("Signed transaction intent message is not a valid string")]
    SignedTransactionIntentMessageIsNotAValidString,
}

// This is required to make an error readable in JavaScript
impl From<Error> for JsValue {
    fn from(value: Error) -> Self {
        JsValue::from_str(&format!("{}", value))
    }
}
