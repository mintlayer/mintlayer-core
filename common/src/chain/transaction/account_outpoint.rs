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

use crate::{chain::DelegationId, primitives::Amount};
use serialization::{Decode, Encode};

// Type of an account that can be used to identify series of spending from an account
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Encode, Decode)]
pub enum AccountType {
    #[codec(index = 0)]
    Delegation(DelegationId),
}

impl From<AccountSpending> for AccountType {
    fn from(spending: AccountSpending) -> Self {
        match spending {
            AccountSpending::Delegation(id, _) => AccountType::Delegation(id),
        }
    }
}

/// The type represents the amount to withdraw from a particular account.
/// It helps solving 2 problems: calculating fees and providing ability to sign input balance with the witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Encode, Decode)]
pub enum AccountSpending {
    #[codec(index = 0)]
    Delegation(DelegationId, Amount),
}

/// Type of OutPoint that represents spending from an account
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Encode, Decode)]
pub struct AccountOutPoint {
    /// An incremental value that represents sequential number of spending from an account.
    /// It's equivalent to the nonce in Ethereum and helps preserving order of transactions and
    /// avoid transaction replay.
    #[codec(compact)]
    nonce: u128,
    /// Type of account to spend from.
    account: AccountSpending,
}

impl AccountOutPoint {
    pub fn new(nonce: u128, account: AccountSpending) -> Self {
        Self { nonce, account }
    }

    pub fn nonce(&self) -> u128 {
        self.nonce
    }

    pub fn account(&self) -> &AccountSpending {
        &self.account
    }
}
