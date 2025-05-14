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

use common::{
    address::AddressError,
    chain::{
        classic_multisig::ClassicMultisigChallengeError,
        signature::{
            inputsig::{
                arbitrary_message::SignArbitraryMessageError,
                authorize_hashed_timelock_contract_spend::AuthorizedHashedTimelockContractSpendTag,
                classical_multisig::authorize_classical_multisig::ClassicalMultisigSigningError,
                InputWitnessTag,
            },
            DestinationSigError,
        },
        IdCreationError, SignedTransactionIntentError, TransactionCreationError,
    },
    size_estimation::SizeEstimationError,
};
use consensus::EffectivePoolBalanceError;
use wasm_bindgen::JsValue;

#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    #[error("Invalid private key encoding: {0}")]
    InvalidPrivateKeyEncoding(serialization::Error),

    #[error("Invalid public key encoding: {0}")]
    InvalidPublicKeyEncoding(serialization::Error),

    #[error("Invalid signature encoding: {0}")]
    InvalidSignatureEncoding(serialization::Error),

    #[error("Invalid outpoint ID encoding: {0}")]
    InvalidOutpointIdEncoding(serialization::Error),

    #[error("Invalid time lock encoding: {0}")]
    InvalidTimeLockEncoding(serialization::Error),

    #[error("Invalid stake pool data encoding: {0}")]
    InvalidStakePoolDataEncoding(serialization::Error),

    #[error("Invalid transaction output encoding: {0}")]
    InvalidOutputEncoding(serialization::Error),

    #[error("Invalid transaction input encoding: {0}")]
    InvalidInputEncoding(serialization::Error),

    #[error("Invalid transaction witness encoding: {0}")]
    InvalidWitnessEncoding(serialization::Error),

    #[error("Invalid transaction encoding: {0}")]
    InvalidTransactionEncoding(serialization::Error),

    #[error("Invalid htlc secret encoding: {0}")]
    InvalidHtlcSecretEncoding(serialization::Error),

    #[error("Invalid multisig challenge encoding: {0}")]
    InvalidMultisigChallengeEncoding(serialization::Error),

    #[error("Invalid signed transaction intent encoding: {0}")]
    InvalidSignedTransactionIntentEncoding(serialization::Error),

    #[error("Error creating multisig spend: {0}")]
    MultisigSpendCreationError(DestinationSigError),

    #[error("Error creating HTLC spend: {0}")]
    HtlcSpendCreationError(DestinationSigError),

    #[error("Error signing a message: {0}")]
    SignMessageError(crypto::key::SignatureError),

    #[error("Invalid mnemonic string: {0}")]
    InvalidMnemonic(bip39::Error),

    #[error("Unexpected HTLC spend type: {0:?}")]
    UnexpectedHtlcSpendType(AuthorizedHashedTimelockContractSpendTag),

    #[error("Unexpected transaction witness type: {0:?}")]
    UnexpectedWitnessType(InputWitnessTag),

    #[error("Invalid key index, MSB bit set")]
    InvalidKeyIndexMsbBitSet,

    #[error("Invalid addressable `{addressable}`: {error}")]
    AddressableParseError {
        addressable: String,
        error: AddressError,
    },

    #[error("Transaction size estimation error: {0}")]
    TransactionSizeEstimationError(SizeEstimationError),

    #[error("Cannot decode NFT creator as a public key: {0}")]
    InvalidNftCreatorPublicKey(serialization::Error),

    #[error("Invalid atoms amount: {atoms}")]
    AtomsAmountParseError { atoms: String },

    #[error("Invalid per thousand {0}, valid range is [0, 1000]")]
    InvalidPerThousand(u16),

    #[error("Multisig signing error: {0}")]
    MultisigSigningError(ClassicalMultisigSigningError),

    #[error("Arbitrary message signing error: {0}")]
    ArbitraryMessageSigningError(SignArbitraryMessageError),

    #[error("Arbitrary message signature verification error: {0}")]
    ArbitraryMessageSignatureVerificationError(DestinationSigError),

    #[error("Input signing error: {0}")]
    InputSigningError(DestinationSigError),

    #[error("Error parsing transaction id: {0}")]
    TransactionIdParseError(fixed_hash::rustc_hex::FromHexError),

    #[error("Error parsing htlc secret hash: {0}")]
    HtlcSecretHashParseError(fixed_hash::rustc_hex::FromHexError),

    #[error("The number of signatures does not match the number of inputs")]
    InvalidWitnessCount,

    #[error("No input outpoint found in transaction")]
    NoInputOutpointFound,

    #[error("Multisig challenge creation error: {0}")]
    MultisigChallengeCreationError(ClassicMultisigChallengeError),

    #[error("Multisig required signatures cannot be zero")]
    ZeroMultisigRequiredSigs,

    #[error("Final supply missing in chain config")]
    FinalSupplyMissingInChainConfig,

    #[error("Calculating effective balance failed: {0}")]
    EffectiveBalanceCalculationFailed(EffectivePoolBalanceError),

    #[error("When fixed total supply is selected an amount must be present as well")]
    FixedTotalSupplyButNoAmount,

    #[error("Invalid token parameters: {0}")]
    InvalidTokenParameters(tx_verifier::error::TokenIssuanceError),

    #[error("Transaction creation error: {0}")]
    TransactionCreationError(TransactionCreationError),

    #[error("Sighash calculation error: {0}")]
    SighashCalculationError(DestinationSigError),

    // Note: IdCreationError already contains the info about which kind of id is being created.
    #[error("Id creation error: {0}")]
    IdCreationError(#[from] IdCreationError),

    #[error("Error decoding a JsValue as an array of arrays of bytes: {error}")]
    JsValueNotArrayOfArraysOfBytes { error: String },

    #[error("Signed transaction intent verification error: {0}")]
    SignedTransactionIntentVerificationError(SignedTransactionIntentError),

    #[error("Signed transaction intent message is not a valid UTF-8 string")]
    SignedTransactionIntentMessageIsNotAValidUtf8String,

    #[error("Orders V1 not activated at the specified height")]
    OrdersV1NotActivatedAtSpecifiedHeight,
}

// This is required to make an error readable in JavaScript
impl From<Error> for JsValue {
    fn from(value: Error) -> Self {
        JsValue::from_str(&format!("{}", value))
    }
}
