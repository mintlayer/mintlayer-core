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

use crate::keys::KeyPurpose;
use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{OutPointSourceId, Transaction},
    primitives::Id,
};
use crypto::key::extended::ExtendedPublicKey;
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

impl serde::Serialize for AccountId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.to_string().serialize(serializer)
    }
}

/// This is a composite id that combines a prefix account id and a generic item id suffix.
/// It is useful for storing key/values that belong to different accounts and are stored in the
/// same map.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct AccountPrefixedId<Id> {
    /// The account id is the prefix and implements HasPrefix for this struct
    account_id: AccountId,
    /// The generic item id. This could be anything, like `Id<Transaction>` or `OutPoint`
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

    pub fn item_id(&self) -> &Id {
        &self.item_id
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }
}

impl<Id: Encode> HasPrefix<AccountId> for AccountPrefixedId<Id> {}

pub type AccountWalletCreatedTxId = AccountPrefixedId<Id<Transaction>>;
pub type AccountWalletTxId = AccountPrefixedId<OutPointSourceId>;
pub type AccountDerivationPathId = AccountPrefixedId<DerivationPath>;
pub type AccountKeyPurposeId = AccountPrefixedId<KeyPurpose>;
pub type AccountAddress = AccountPrefixedId<PublicKeyHash>;
