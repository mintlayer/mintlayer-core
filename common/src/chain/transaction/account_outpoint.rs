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

use crate::{
    chain::{tokens::TokenId, AccountNonce, DelegationId},
    primitives::Amount,
};
use serialization::{Decode, Encode};

/// Type of an account that can be used to identify series of spending from an account
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Encode, Decode)]
pub enum AccountType {
    #[codec(index = 0)]
    Delegation(DelegationId),
    /// Token account type is used to authorize changes in supply of a token.
    #[codec(index = 1)]
    TokenSupply(TokenId),
}

impl From<AccountSpending> for AccountType {
    fn from(spending: AccountSpending) -> Self {
        match spending {
            AccountSpending::Delegation(id, _) => AccountType::Delegation(id),
            AccountSpending::TokenUnrealizedSupply(id, _)
            | AccountSpending::TokenCirculatingSupply(id, _)
            | AccountSpending::TokenSupplyLock(id) => AccountType::TokenSupply(id),
        }
    }
}

/// The type represents the amount to withdraw from a particular account.
/// Otherwise it's unclear how much should be deducted from an account balance.
/// It also helps solving 2 additional problems: calculating fees and providing ability to sign input balance with the witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Encode, Decode, serde::Serialize)]
pub enum AccountSpending {
    #[codec(index = 0)]
    Delegation(DelegationId, Amount),
    #[codec(index = 1)]
    TokenUnrealizedSupply(TokenId, Amount),
    #[codec(index = 2)]
    TokenCirculatingSupply(TokenId, Amount),
    #[codec(index = 3)]
    TokenSupplyLock(TokenId),
}

/// Type of OutPoint that represents spending from an account
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Encode, Decode, serde::Serialize)]
pub struct AccountOutPoint {
    nonce: AccountNonce,
    account: AccountSpending,
}

impl AccountOutPoint {
    pub fn new(nonce: AccountNonce, account: AccountSpending) -> Self {
        Self { nonce, account }
    }

    pub fn nonce(&self) -> AccountNonce {
        self.nonce
    }

    pub fn account(&self) -> &AccountSpending {
        &self.account
    }
}
