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

use std::sync::Arc;

use common::chain::{
    signature::{
        inputsig::{
            arbitrary_message::{ArbitraryMessageSignature, SignArbitraryMessageError},
            classical_multisig::multisig_partial_signature::PartiallySignedMultisigStructureError,
        },
        DestinationSigError,
    },
    ChainConfig, Destination,
};
use crypto::key::hdkd::{derivable::DerivationError, u31::U31};
use wallet_storage::{
    WalletStorageReadLocked, WalletStorageReadUnlocked, WalletStorageWriteUnlocked,
};
use wallet_types::{
    partially_signed_transaction::PartiallySignedTransaction, signature_status::SignatureStatus,
    AccountId,
};

use crate::{
    key_chain::{AccountKeyChains, KeyChainError},
    Account, WalletResult,
};

pub mod software_signer;
#[cfg(feature = "trezor")]
pub mod trezor_signer;

#[cfg(feature = "trezor")]
use self::trezor_signer::TrezorError;

/// Signer errors
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
    #[error("{0}")]
    MultisigError(#[from] PartiallySignedMultisigStructureError),
    #[error("{0}")]
    SerializationError(#[from] serialization::Error),
    #[cfg(feature = "trezor")]
    #[error("Trezor error: {0}")]
    TrezorError(#[from] TrezorError),
    #[error("Partially signed tx is missing input's destination")]
    MissingDestinationInTransaction,
    #[error("Partially signed tx is missing UTXO type input's UTXO")]
    MissingUtxo,
    #[error("Partially signed tx is missing extra info for UTXO")]
    MissingUtxoExtraInfo,
    #[error("Tokens V0 are not supported")]
    UnsupportedTokensV0,
}

type SignerResult<T> = Result<T, SignerError>;

/// Signer trait responsible for signing transactions or challenges using a software or hardware
/// wallet
pub trait Signer {
    /// sign a partially signed transaction and return the before and after signature statuses
    fn sign_tx(
        &mut self,
        tx: PartiallySignedTransaction,
        key_chain: &impl AccountKeyChains,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> SignerResult<(
        PartiallySignedTransaction,
        Vec<SignatureStatus>,
        Vec<SignatureStatus>,
    )>;

    /// sign an arbitrary message for a destination known to this key chain
    fn sign_challenge(
        &mut self,
        message: Vec<u8>,
        destination: Destination,
        key_chain: &impl AccountKeyChains,
        db_tx: &impl WalletStorageReadUnlocked,
    ) -> SignerResult<ArbitraryMessageSignature>;
}

pub trait SignerProvider {
    type S: Signer;
    type K: AccountKeyChains;

    fn provide(&mut self, chain_config: Arc<ChainConfig>, account_index: U31) -> Self::S;

    fn make_new_account(
        &mut self,
        chain_config: Arc<ChainConfig>,
        account_index: U31,
        name: Option<String>,
        db_tx: &mut impl WalletStorageWriteUnlocked,
    ) -> WalletResult<Account<Self::K>>;

    fn load_account_from_database(
        &self,
        chain_config: Arc<ChainConfig>,
        db_tx: &impl WalletStorageReadLocked,
        id: &AccountId,
    ) -> WalletResult<Account<Self::K>>;
}
