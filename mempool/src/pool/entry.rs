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

use super::{Fee, Time, TxOrigin};

/// A dependency of a transaction on a previous account state.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TxAccountDependency {
    delegation_id: DelegationId,
    nonce: AccountNonce,
}

impl TxAccountDependency {
    pub fn new(delegation_id: DelegationId, nonce: AccountNonce) -> Self {
        TxAccountDependency {
            delegation_id,
            nonce,
        }
    }
}

/// A dependency of a transaction. May be another transaction or a previous account state.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxDependency {
    DelegationAccount(TxAccountDependency),
    TxOutput(Id<Transaction>, u32),
    // TODO: Block reward?
}

impl TxDependency {
    fn from_utxo(outpt: &UtxoOutPoint) -> Option<Self> {
        outpt.tx_id().get_tx_id().map(|id| Self::TxOutput(*id, outpt.output_index()))
    }

    fn from_account(acct: &AccountSpending, nonce: AccountNonce) -> Self {
        match acct {
            AccountSpending::Delegation(delegation_id, _) => {
                Self::DelegationAccount(TxAccountDependency::new(*delegation_id, nonce))
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
            TxInput::Utxo(_) => None,
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
    origin: TxOrigin,
}

impl TxEntry {
    /// Create a new mempool transaction entry
    pub fn new(transaction: SignedTransaction, creation_time: Time, origin: TxOrigin) -> Self {
        let tx_id = transaction.transaction().get_id();
        let encoded_size = serialization::Encode::encoded_size(&transaction);
        Self {
            tx_id,
            transaction,
            creation_time,
            encoded_size,
            origin,
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

    /// Where we got this transaction
    pub fn origin(&self) -> TxOrigin {
        self.origin
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
