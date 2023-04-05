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

use common::address::pubkeyhash::PublicKeyHash;
use common::chain::{OutPoint, Transaction};
use common::primitives::Id;
use crypto::key::extended::ExtendedPublicKey;
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::hdkd::derivation_path::DerivationPath;
use serialization::{Decode, Encode};
use storage::HasPrefix;

/// The account id is described by it's public key hash or a random value for
/// non deterministic accounts
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct AccountId(PublicKeyHash);

impl AccountId {
    pub fn new_from_xpub(pub_key: &ExtendedPublicKey) -> Self {
        let pk = pub_key.clone().into_public_key();
        let pkh = PublicKeyHash::from(&pk);
        AccountId(pkh)
    }
}

/// Account metadata that contains information like from which master key it was derived from
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum AccountInfo {
    #[codec(index = 0)]
    Deterministic(DeterministicAccountInfo),
}

/// Struct that holds information for account addresses
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct KeychainUsageState {
    /// Last used address index. An address might not be used so the corresponding entry would be
    /// None, otherwise it would be that last used ChildNumber
    last_used: Option<ChildNumber>,
    /// Last issued address to the user. Those addresses can be issued until the
    /// last used index + lookahead size.
    last_issued: Option<ChildNumber>,
}

impl KeychainUsageState {
    pub fn new(last_used: Option<ChildNumber>, last_issued: Option<ChildNumber>) -> Self {
        Self {
            last_used,
            last_issued,
        }
    }

    /// Get the last index used in the blockchain
    pub fn get_last_used(&self) -> Option<ChildNumber> {
        self.last_used
    }

    /// Set the last index used in the blockchain
    pub fn set_last_used(&mut self, new_last_used: Option<ChildNumber>) {
        self.last_used = new_last_used;
    }

    /// Get the last index issued to the user
    pub fn get_last_issued(&self) -> Option<ChildNumber> {
        self.last_issued
    }

    /// Set the last index issued to the user
    pub fn set_last_issued(&mut self, new_last_issued: Option<ChildNumber>) {
        self.last_issued = new_last_issued;
    }
}

/// Serialized data for deterministic accounts. The fields are documented in `AccountKeyChain`.
// TODO tbd what metadata we need to store
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct DeterministicAccountInfo {
    root_hierarchy_key: Option<ExtendedPublicKey>,
    account_key: ExtendedPublicKey,
    lookahead_size: u16,
    // TODO store separately
    receiving_state: KeychainUsageState,
    change_state: KeychainUsageState,
}

impl DeterministicAccountInfo {
    pub fn new(
        root_hierarchy_key: Option<ExtendedPublicKey>,
        account_key: ExtendedPublicKey,
        lookahead_size: u16,
        receiving_state: KeychainUsageState,
        change_state: KeychainUsageState,
    ) -> Self {
        Self {
            root_hierarchy_key,
            account_key,
            lookahead_size,
            receiving_state,
            change_state,
        }
    }

    pub fn get_root_hierarchy_key(&self) -> &Option<ExtendedPublicKey> {
        &self.root_hierarchy_key
    }

    pub fn get_account_key(&self) -> &ExtendedPublicKey {
        &self.account_key
    }

    pub fn get_lookahead_size(&self) -> u16 {
        self.lookahead_size
    }

    pub fn get_receiving_state(&self) -> &KeychainUsageState {
        &self.receiving_state
    }

    pub fn get_change_state(&self) -> &KeychainUsageState {
        &self.change_state
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct AccountPrefixedId<Id> {
    account_id: AccountId,
    item_id: Id,
}

impl<Id: Encode> AccountPrefixedId<Id> {
    pub fn new(account_id: AccountId, item_id: Id) -> AccountPrefixedId<Id> {
        Self {
            account_id,
            item_id,
        }
    }

    pub fn into_item_id(self) -> Id {
        self.item_id
    }
}

impl<ID: Encode> HasPrefix<AccountId> for AccountPrefixedId<ID> {}

pub type AccountTxId = AccountPrefixedId<Id<Transaction>>;
pub type AccountAddressId = AccountPrefixedId<DerivationPath>;
pub type AccountOutPointId = AccountPrefixedId<OutPoint>;
