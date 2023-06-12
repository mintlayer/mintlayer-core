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

use common::{
    chain::{
        AccountNonce, AccountSpending, DelegationId, SignedTransaction, Transaction, TxInput,
        UtxoOutPoint,
    },
    primitives::{Id, Idable},
};

use super::{Fee, Time};

/// A dependency of a transaction. May be another transaction or a previous account state.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxDependency {
    DelegationAccount(DelegationId, AccountNonce),
    Transaction(Id<Transaction>),
    // TODO: Block reward?
}

impl TxDependency {
    fn from_utxo(outpt: &UtxoOutPoint) -> Option<Self> {
        outpt.tx_id().get_tx_id().map(|id| Self::Transaction(*id))
    }

    fn from_account(acct: &AccountSpending, nonce: AccountNonce) -> Self {
        match acct {
            AccountSpending::Delegation(delegation_id, _) => {
                Self::DelegationAccount(*delegation_id, nonce)
            }
        }
    }

    fn from_input_requires(input: &TxInput) -> Option<Self> {
        match input {
            TxInput::Utxo(utxo) => Self::from_utxo(utxo),
            TxInput::Account(acct) => {
                acct.nonce().decrement().map(|nonce| Self::from_account(acct.account(), nonce))
            }
        }
    }

    fn from_input_provides(input: &TxInput) -> Option<Self> {
        match input {
            TxInput::Utxo(_) => None, // handled at transaction level
            TxInput::Account(acct) => Some(Self::from_account(acct.account(), acct.nonce())),
        }
    }
}

/// A transaction together with its creation time
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxEntry {
    tx_id: Id<Transaction>,
    transaction: SignedTransaction,
    creation_time: Time,
    encoded_size: usize,
}

impl TxEntry {
    /// Create a new mempool transaction entry
    pub fn new(transaction: SignedTransaction, creation_time: Time) -> Self {
        let tx_id = transaction.transaction().get_id();
        let encoded_size = serialization::Encode::encoded_size(&transaction);
        Self {
            tx_id,
            transaction,
            creation_time,
            encoded_size,
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
    pub fn size(&self) -> usize {
        self.encoded_size
    }

    /// Dependency graph edges this entry requires
    pub fn requires(&self) -> impl Iterator<Item = TxDependency> + '_ {
        self.inputs_iter().filter_map(TxDependency::from_input_requires)
    }

    /// Dependency graph edges this entry provides
    pub fn provides(&self) -> impl Iterator<Item = TxDependency> + '_ {
        std::iter::once(TxDependency::Transaction(*self.tx_id()))
            .chain(self.inputs_iter().filter_map(TxDependency::from_input_provides))
    }

    fn inputs_iter(&self) -> impl Iterator<Item = &TxInput> + ExactSizeIterator + '_ {
        self.transaction().inputs().iter()
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

    pub fn transaction(&self) -> &SignedTransaction {
        self.entry.transaction()
    }

    pub fn fee(&self) -> Fee {
        self.fee
    }

    pub fn into_entry_and_fee(self) -> (TxEntry, Fee) {
        let Self { entry, fee } = self;
        (entry, fee)
    }
}
