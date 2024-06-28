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

use std::collections::{btree_map::Entry, BTreeMap};

use common::{
    chain::{AccountSpending, AccountType, DelegationId},
    primitives::Amount,
};
use pos_accounting::PoSAccountingView;

use crate::Error;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
enum GenericAccountId {
    Delegation(DelegationId),
}

impl From<AccountSpending> for GenericAccountId {
    fn from(account: AccountSpending) -> Self {
        match account {
            AccountSpending::DelegationBalance(id, _) => Self::Delegation(id),
        }
    }
}

impl From<GenericAccountId> for AccountType {
    fn from(value: GenericAccountId) -> Self {
        match value {
            GenericAccountId::Delegation(id) => AccountType::Delegation(id),
        }
    }
}

pub struct AccountsBalancesTracker<P> {
    balances: BTreeMap<GenericAccountId, Amount>,

    pos_accounting_view: P,
}

impl<P: PoSAccountingView> AccountsBalancesTracker<P> {
    pub fn new(pos_accounting_view: P) -> Self {
        Self {
            balances: BTreeMap::new(),
            pos_accounting_view,
        }
    }

    pub fn spend_from_account(&mut self, account: AccountSpending) -> Result<(), Error> {
        match self.balances.entry(account.clone().into()) {
            Entry::Vacant(e) => {
                let (balance, spending) = match account {
                    AccountSpending::DelegationBalance(id, spending) => {
                        let balance = self
                            .pos_accounting_view
                            .get_delegation_balance(id)
                            .map_err(|_| pos_accounting::Error::ViewFail)?
                            .ok_or(Error::AccountBalanceNotFound(account.clone().into()))?;
                        (balance, spending)
                    }
                };
                let new_balance = (balance - spending)
                    .ok_or(Error::NegativeAccountBalance(account.clone().into()))?;
                e.insert(new_balance);
            }
            Entry::Occupied(mut e) => {
                let balance = e.get_mut();
                let spending = match account {
                    AccountSpending::DelegationBalance(_, spending) => spending,
                };
                *balance = (*balance - spending)
                    .ok_or(Error::NegativeAccountBalance(account.clone().into()))?;
            }
        };
        Ok(())
    }
}
