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

use crate::chain::DelegationId;
use crate::primitives::Amount;
use serialization::{Decode, Encode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Encode, Decode)]
pub enum AccountType {
    Delegation(DelegationId),
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Encode, Decode)]
pub struct AccountOutPoint {
    #[codec(compact)]
    nonce: u128,
    account: AccountType,
    withdraw_amount: Amount,
}

impl AccountOutPoint {
    pub fn new(nonce: u128, account: AccountType, withdraw_amount: Amount) -> Self {
        Self {
            nonce,
            account,
            withdraw_amount,
        }
    }

    pub fn nonce(&self) -> u128 {
        self.nonce
    }

    pub fn account(&self) -> &AccountType {
        &self.account
    }

    pub fn withdraw_amount(&self) -> &Amount {
        &self.withdraw_amount
    }
}
