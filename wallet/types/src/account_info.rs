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

// TODO tbd what metadata we need to store
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct DeterministicAccountInfo {
    pub root_hierarchy_key: Option<ExtendedPublicKey>,
    pub account_key: ExtendedPublicKey,
    pub lookahead_size: u16,
    // TODO store separately
    pub last_used: [Option<ChildNumber>; 2],
    pub last_issued: [Option<ChildNumber>; 2],
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct AccountPrefixedId<ID: Encode> {
    account_id: AccountId,
    item_id: ID,
}

impl<ID: Encode> AccountPrefixedId<ID> {
    pub fn new(account_id: AccountId, item_id: ID) -> AccountPrefixedId<ID> {
        Self {
            account_id,
            item_id,
        }
    }

    pub fn into_item_id(self) -> ID {
        self.item_id
    }
}

impl<ID: Encode> HasPrefix<AccountId> for AccountPrefixedId<ID> {}

pub type AccountTxId = AccountPrefixedId<Id<Transaction>>;
pub type AccountAddressId = AccountPrefixedId<DerivationPath>;
pub type AccountOutPointId = AccountPrefixedId<OutPoint>;
