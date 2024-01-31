// Copyright (c) 2022 RBB S.r.l
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
    chain::{AccountSpending, AccountType, DelegationId, Transaction, TxInput, TxOutput},
    primitives::Amount,
};
use pos_accounting::PoSAccountingView;

use super::IOPolicyError;

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

pub fn check_accounts_balances_overspend(
    tx: &Transaction,
    pos_accounting_view: &impl PoSAccountingView,
) -> Result<(), IOPolicyError> {
    let mut balances = BTreeMap::<GenericAccountId, Amount>::new();

    // if an outputs top up account's balance it should be accounted calculation
    for output in tx.outputs() {
        match output {
            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::Burn(_)
            | TxOutput::CreateStakePool(_, _)
            | TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::DataDeposit(_) => { /* skip */ }
            TxOutput::DelegateStaking(delegated_amount, delegation_id) => {
                let account = GenericAccountId::Delegation(*delegation_id);
                match balances.entry(account) {
                    Entry::Vacant(e) => {
                        let balance = pos_accounting_view
                            .get_delegation_balance(*delegation_id)
                            .map_err(|_| pos_accounting::Error::ViewFail)?
                            .unwrap_or(Amount::ZERO);
                        let new_balance = (balance + *delegated_amount)
                            .ok_or(IOPolicyError::AccountBalanceOverflow(account.into()))?;
                        e.insert(new_balance);
                    }
                    Entry::Occupied(mut e) => {
                        let balance = e.get_mut();
                        *balance = (*balance + *delegated_amount)
                            .ok_or(IOPolicyError::AccountBalanceOverflow(account.into()))?;
                    }
                };
            }
        }
    }

    for input in tx.inputs() {
        match input {
            TxInput::Utxo(_) | TxInput::AccountCommand(_, _) => { /* skip */ }
            TxInput::Account(account_outpoint) => match account_outpoint.account() {
                AccountSpending::DelegationBalance(delegation_id, spend_amount) => {
                    let account = account_outpoint.account().clone().into();
                    match balances.entry(account) {
                        Entry::Vacant(e) => {
                            let balance = pos_accounting_view
                                .get_delegation_balance(*delegation_id)
                                .map_err(|_| pos_accounting::Error::ViewFail)?
                                .ok_or(IOPolicyError::AccountBalanceNotFound(account.into()))?;
                            let new_balance = (balance - *spend_amount)
                                .ok_or(IOPolicyError::NegativeAccountBalance(account.into()))?;
                            e.insert(new_balance);
                        }
                        Entry::Occupied(mut e) => {
                            let balance = e.get_mut();
                            *balance = (*balance - *spend_amount)
                                .ok_or(IOPolicyError::NegativeAccountBalance(account.into()))?;
                        }
                    };
                }
            },
        }
    }

    Ok(())
}
