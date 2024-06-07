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
    signature::{
        inputsig::arbitrary_message::{ArbitraryMessageSignature, SignArbitraryMessageError},
        DestinationSigError,
    },
    Destination,
};
use crypto::key::hdkd::derivable::DerivationError;
use wallet_types::signature_status::SignatureStatus;

use crate::{
    account::PartiallySignedTransaction,
    key_chain::{AccountKeyChains, KeyChainError},
};

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
    #[error("{0}")]
    SignArbitraryMessageError(#[from] SignArbitraryMessageError),
}

type SignerResult<T> = Result<T, SignerError>;

/// Signer trait responsible for signing transactions or challenges using a software or hardware
/// wallet
pub trait Signer {
    /// sign a partially signed transaction and return the before and after signature statuses
    fn sign_ptx(
        &self,
        tx: PartiallySignedTransaction,
        key_chain: &impl AccountKeyChains,
    ) -> SignerResult<(
        PartiallySignedTransaction,
        Vec<SignatureStatus>,
        Vec<SignatureStatus>,
    )>;

    /// sign an arbitrary message for a destination known to this key chain
    fn sign_challenge(
        &self,
        message: Vec<u8>,
        destination: Destination,
        key_chain: &impl AccountKeyChains,
    ) -> SignerResult<ArbitraryMessageSignature>;
}
