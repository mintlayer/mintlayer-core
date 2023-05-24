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

use common::address::Address;
use crypto::key::extended::ExtendedPublicKey;
use wallet_types::{
    account_id::AccountBlockHeight, wallet_block::WalletBlock, AccountDerivationPathId, AccountId,
    AccountInfo, AccountKeyPurposeId, AccountTxId, KeychainUsageState, RootKeyContent, RootKeyId,
    WalletTx,
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
        /// Store for all the private keys in this wallet
        pub DBRootKeys: Map<RootKeyId, RootKeyContent>,
        /// Store for all the public keys in this wallet
        pub DBPubKeys: Map<AccountDerivationPathId, ExtendedPublicKey>,
        /// Store for all the addresses that belong to an account
        pub DBAddresses: Map<AccountDerivationPathId, Address>,
        /// Store for WalletBlock
        pub DBBlocks: Map<AccountBlockHeight, WalletBlock>,
        /// Store for Transaction entries
        pub DBTxs: Map<AccountTxId, WalletTx>,
    }
}
