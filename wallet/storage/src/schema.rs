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

//! Wallet database schema

use common::chain::SignedTransaction;
use crypto::key::extended::ExtendedPublicKey;
use utils::maybe_encrypted::MaybeEncrypted;
use wallet_types::{
    account_id::{AccountAddress, AccountPublicKey},
    account_info::{
        AccountVrfKeys, StandaloneMultisig, StandalonePrivateKey, StandaloneWatchOnlyKey,
    },
    keys::{RootKeyConstant, RootKeys},
    seed_phrase::{SeedPhraseConstant, SerializableSeedPhrase},
    AccountDerivationPathId, AccountId, AccountInfo, AccountKeyPurposeId, AccountWalletCreatedTxId,
    AccountWalletTxId, KeychainUsageState, WalletTx,
};

storage::decl_schema! {
    /// Database schema for wallet storage
    pub Schema {
        /// Storage for individual values.
        pub DBValue: Map<Vec<u8>, Vec<u8>>,
        /// Store for all the accounts in this wallet
        pub DBAccounts: Map<AccountId, AccountInfo>,
        /// Store keychain usage states
        pub DBKeychainUsageStates: Map<AccountKeyPurposeId, KeychainUsageState>,
        /// Store keychain usage states
        pub DBVrfKeychainUsageStates: Map<AccountId, KeychainUsageState>,
        /// Store for all the private keys in this wallet
        pub DBRootKeys: Map<RootKeyConstant, MaybeEncrypted<RootKeys>>,
        /// Store for all the public keys in this wallet
        pub DBPubKeys: Map<AccountDerivationPathId, ExtendedPublicKey>,
        /// Store for all the addresses that belong to an account
        pub DBAddresses: Map<AccountDerivationPathId, String>,
        /// Store for block/transaction entries
        pub DBTxs: Map<AccountWalletTxId, WalletTx>,
        /// Store for wallet created transactions
        pub DBUserTx: Map<AccountWalletCreatedTxId, SignedTransaction>,
        /// Store for the wallet's passphrase
        pub DBSeedPhrase: Map<SeedPhraseConstant, MaybeEncrypted<SerializableSeedPhrase>>,
        /// Store for each account's unconfirmed transaction order counter
        pub DBUnconfirmedTxCounters: Map<AccountId, u64>,
        /// Store for each account's legacy VRF public key
        pub DBVRFPublicKeys: Map<AccountId, AccountVrfKeys>,
        /// Store for standalone watch only keys added to accounts
        pub DBStandaloneWatchOnlyKeys: Map<AccountAddress, StandaloneWatchOnlyKey>,
        /// Store for standalone multisig keys added to accounts
        pub DBStandaloneMultisigKeys: Map<AccountAddress, StandaloneMultisig>,
        /// Store for standalone private keys added to accounts
        pub DBStandalonePrivateKeys: Map<AccountPublicKey, StandalonePrivateKey>,
    }
}
