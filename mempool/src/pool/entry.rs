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
    chain::{SignedTransaction, Transaction},
    primitives::{Id, Idable},
};

use super::{Fee, Time, TxOptions, TxOrigin};
use crate::{
    pool::dependency::{TxProvidedNonUtxoDependency, TxRequiredDependency},
    tx_origin::IsOrigin,
};

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
    pub fn required_deps(&self) -> impl Iterator<Item = TxRequiredDependency> + '_ {
        TxRequiredDependency::from_tx(self)
    }

    /// Dependency graph edges this entry provides
    pub fn provided_non_utxo_deps(&self) -> impl Iterator<Item = TxProvidedNonUtxoDependency> + '_ {
        TxProvidedNonUtxoDependency::from_tx(self)
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
