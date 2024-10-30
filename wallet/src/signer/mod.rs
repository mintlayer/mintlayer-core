// Copyright (c) 2024 RBB S.r.l
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
    partially_signed_transaction::PartiallySignedTransaction,
    signature::{
        inputsig::arbitrary_message::{ArbitraryMessageSignature, SignArbitraryMessageError},
        DestinationSigError,
    },
    Destination, SignedTransactionIntent, SignedTransactionIntentError, Transaction,
};
use crypto::key::hdkd::derivable::DerivationError;
use wallet_types::signature_status::SignatureStatus;

use crate::key_chain::{AccountKeyChains, KeyChainError};

pub mod software_signer;

/// KeyChain errors
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum SignerError {
    #[error("The provided keys do not belong to the same hierarchy")]
    KeysNotInSameHierarchy,
    #[error("Key derivation error: {0}")]
    Derivation(#[from] DerivationError),
    #[error("Signing error: {0}")]
    SigningError(#[from] DestinationSigError),
    #[error("Wallet database error: {0}")]
    DatabaseError(#[from] wallet_storage::Error),
    #[error("Keychain error: {0}")]
    KeyChainError(#[from] KeyChainError),
    #[error("Destination does not belong to this wallet")]
    DestinationNotFromThisWallet,
    #[error("Error signing arbitrary message: {0}")]
    SignArbitraryMessageError(#[from] SignArbitraryMessageError),
    #[error("Signed transaction intent error: {0}")]
    SignedTransactionIntentError(#[from] SignedTransactionIntentError),
}

type SignerResult<T> = Result<T, SignerError>;

/// Signer trait responsible for signing transactions or challenges using a software or hardware
/// wallet
pub trait Signer {
    /// Sign a partially signed transaction and return the before and after signature statuses.
    fn sign_tx(
        &self,
        tx: PartiallySignedTransaction,
        key_chain: &impl AccountKeyChains,
    ) -> SignerResult<(
        PartiallySignedTransaction,
        Vec<SignatureStatus>,
        Vec<SignatureStatus>,
    )>;

    /// Sign an arbitrary message for a destination known to this key chain.
    fn sign_challenge(
        &self,
        message: &[u8],
        destination: &Destination,
        key_chain: &impl AccountKeyChains,
    ) -> SignerResult<ArbitraryMessageSignature>;

    /// Sign a transaction intent. The number of `input_destinations` must be the same as
    /// the number of inputs in the transaction; all of the destinations must be known
    /// to this key chain.
    fn sign_transaction_intent(
        &self,
        transaction: &Transaction,
        input_destinations: &[Destination],
        intent: &str,
        key_chain: &impl AccountKeyChains,
    ) -> SignerResult<SignedTransactionIntent>;
}
