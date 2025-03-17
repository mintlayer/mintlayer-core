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

use std::num::NonZeroUsize;

use common::{
    chain::{
        AccountCommand, AccountNonce, AccountSpending, AccountType, OrderAccountCommand,
        SignedTransaction, Transaction, TxInput, UtxoOutPoint,
    },
    primitives::{Id, Idable},
};

use super::{Fee, Time, TxOptions, TxOrigin};
use crate::tx_origin::IsOrigin;

/// A dependency of a transaction on a previous account state.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TxAccountDependency {
    account: AccountType,
    nonce: AccountNonce,
}

impl TxAccountDependency {
    pub fn new(account: AccountType, nonce: AccountNonce) -> Self {
        TxAccountDependency { account, nonce }
    }
}

/// A dependency of a transaction. May be another transaction or a previous account state.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxDependency {
    DelegationAccount(TxAccountDependency),
    TokenSupplyAccount(TxAccountDependency),
    OrderAccount(TxAccountDependency),
    // TODO: keep only V1 version after OrdersVersion::V1 is activated
    OrderV1Account(AccountType),
    TxOutput(Id<Transaction>, u32),
    // TODO: Block reward?
}

impl TxDependency {
    fn from_utxo(output: &UtxoOutPoint) -> Option<Self> {
        output
            .source_id()
            .get_tx_id()
            .map(|id| Self::TxOutput(*id, output.output_index()))
    }

    fn from_account(account: &AccountSpending, nonce: AccountNonce) -> Self {
        match account {
            AccountSpending::DelegationBalance(_, _) => {
                Self::DelegationAccount(TxAccountDependency::new(account.clone().into(), nonce))
            }
        }
    }

    fn from_account_cmd(cmd: &AccountCommand, nonce: AccountNonce) -> Self {
        match cmd {
            AccountCommand::MintTokens(_, _)
            | AccountCommand::UnmintTokens(_)
            | AccountCommand::LockTokenSupply(_)
            | AccountCommand::FreezeToken(_, _)
            | AccountCommand::UnfreezeToken(_)
            | AccountCommand::ChangeTokenMetadataUri(_, _)
            | AccountCommand::ChangeTokenAuthority(_, _) => {
                Self::TokenSupplyAccount(TxAccountDependency::new(cmd.clone().into(), nonce))
            }
            AccountCommand::ConcludeOrder(_) | AccountCommand::FillOrder(_, _, _) => {
                Self::OrderAccount(TxAccountDependency::new(cmd.clone().into(), nonce))
            }
        }
    }
    fn from_order_account_cmd(cmd: &OrderAccountCommand) -> Self {
        Self::OrderV1Account(cmd.clone().into())
    }

    fn from_input_requires(input: &TxInput) -> Option<Self> {
        match input {
            TxInput::Utxo(utxo) => Self::from_utxo(utxo),
            TxInput::Account(acct) => {
                acct.nonce().decrement().map(|nonce| Self::from_account(acct.account(), nonce))
            }
            TxInput::AccountCommand(nonce, op) => {
                nonce.decrement().map(|nonce| Self::from_account_cmd(op, nonce))
            }
            TxInput::OrderAccountCommand(cmd) => Some(Self::from_order_account_cmd(cmd)),
        }
    }

    fn from_input_provides(input: &TxInput) -> Option<Self> {
        match input {
            TxInput::Utxo(_) => None,
            TxInput::Account(acct) => Some(Self::from_account(acct.account(), acct.nonce())),
            TxInput::AccountCommand(nonce, op) => Some(Self::from_account_cmd(op, *nonce)),
            TxInput::OrderAccountCommand(cmd) => Some(Self::from_order_account_cmd(cmd)),
        }
    }
}

/// A transaction together with its creation time
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxEntry<O = TxOrigin> {
    tx_id: Id<Transaction>,
    transaction: SignedTransaction,
    creation_time: Time,
    encoded_size: NonZeroUsize,
    origin: O,
    options: TxOptions,
}

impl<O: IsOrigin> TxEntry<O> {
    /// Create a new mempool transaction entry
    pub fn new(
        transaction: SignedTransaction,
        creation_time: Time,
        origin: O,
        options: TxOptions,
    ) -> Self {
        let tx_id = transaction.transaction().get_id();
        let encoded_size = serialization::Encode::encoded_size(&transaction);
        let encoded_size = NonZeroUsize::new(encoded_size).expect("Encoded tx size is non-zero");
        Self {
            tx_id,
            transaction,
            creation_time,
            encoded_size,
            origin,
            options,
        }
    }

    /// Underlying transaction
    pub fn transaction(&self) -> &SignedTransaction {
        &self.transaction
    }

    /// When was the entry created, e.g. when it was received by a peer
    pub fn creation_time(&self) -> Time {
        self.creation_time
    }

    /// Transaction ID
    pub fn tx_id(&self) -> &Id<Transaction> {
        &self.tx_id
    }

    /// Encoded size of this entry
    pub fn size(&self) -> NonZeroUsize {
        self.encoded_size
    }

    /// Where we got this transaction
    pub fn origin(&self) -> O {
        self.origin
    }

    /// Get transaction processing options
    pub fn options(&self) -> &TxOptions {
        &self.options
    }

    /// Dependency graph edges this entry requires
    pub fn requires(&self) -> impl Iterator<Item = TxDependency> + '_ {
        self.inputs_iter().filter_map(TxDependency::from_input_requires)
    }

    /// Dependency graph edges this entry provides
    pub fn provides(&self) -> impl Iterator<Item = TxDependency> + '_ {
        let n_outputs = self.transaction().outputs().len() as u32;
        let from_outputs = (0..n_outputs).map(|i| TxDependency::TxOutput(*self.tx_id(), i));
        let from_inputs = self.inputs_iter().filter_map(TxDependency::from_input_provides);
        from_outputs.chain(from_inputs)
    }

    fn inputs_iter(&self) -> impl ExactSizeIterator<Item = &TxInput> + '_ {
        self.transaction().inputs().iter()
    }

    pub fn map_origin<R: IsOrigin>(self, func: impl FnOnce(O) -> R) -> TxEntry<R> {
        self.try_map_origin::<R, std::convert::Infallible>(|o| Ok(func(o)))
            .unwrap_or_else(|(_, e)| match e {})
    }

    pub fn try_map_origin<R: IsOrigin, E>(
        self,
        func: impl FnOnce(O) -> Result<R, E>,
    ) -> Result<TxEntry<R>, (Self, E)> {
        match func(self.origin) {
            Ok(origin) => {
                let TxEntry {
                    tx_id,
                    transaction,
                    creation_time,
                    encoded_size,
                    origin: _,
                    options,
                } = self;

                Ok(TxEntry {
                    tx_id,
                    transaction,
                    creation_time,
                    encoded_size,
                    origin,
                    options,
                })
            }
            Err(err) => Err((self, err)),
        }
    }
}

/// A transaction entry [TxEntry] together with fee info
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxEntryWithFee {
    entry: TxEntry,
    fee: Fee,
}

impl TxEntryWithFee {
    pub fn new(entry: TxEntry, fee: Fee) -> Self {
        Self { entry, fee }
    }

    pub fn tx_id(&self) -> &Id<Transaction> {
        self.entry.tx_id()
    }

    pub fn tx_entry(&self) -> &TxEntry {
        &self.entry
    }

    pub fn transaction(&self) -> &SignedTransaction {
        self.entry.transaction()
    }

    pub fn fee(&self) -> Fee {
        self.fee
    }

    pub fn into_tx_entry(self) -> TxEntry {
        self.entry
    }
}
