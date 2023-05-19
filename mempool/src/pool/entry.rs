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
    chain::{SignedTransaction, Transaction},
    primitives::{Id, Idable},
};

use super::{Fee, Time};

/// A transaction together with its creation time
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxEntry {
    tx_id: Id<Transaction>,
    transaction: SignedTransaction,
    creation_time: Time,
}

impl TxEntry {
    pub fn new(transaction: SignedTransaction, creation_time: Time) -> Self {
        let tx_id = transaction.transaction().get_id();
        Self {
            tx_id,
            transaction,
            creation_time,
        }
    }

    pub fn transaction(&self) -> &SignedTransaction {
        &self.transaction
    }

    pub fn creation_time(&self) -> Time {
        self.creation_time
    }

    pub fn tx_id(&self) -> &Id<Transaction> {
        &self.tx_id
    }

    pub fn size(&self) -> usize {
        serialization::Encode::encoded_size(self.transaction())
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
