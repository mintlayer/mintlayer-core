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
        tokens::TokenId, AccountCommand, AccountNonce, AccountSpending, DelegationId, OrderId,
        SignedTransaction, Transaction, TxInput, UtxoOutPoint,
    },
    primitives::{Id, Idable},
};

use super::{Fee, Time, TxOptions, TxOrigin};
use crate::tx_origin::IsOrigin;

/// A dependency of a transaction. May be another transaction or a previous account state.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxDependency {
    DelegationAccount(DelegationId, AccountNonce),
    TokenSupplyAccount(TokenId, AccountNonce),
    // TODO: remove OrderV0Account after OrdersVersion::V1 is activated
    //       https://github.com/mintlayer/mintlayer-core/issues/1901
    OrderV0Account(OrderId, AccountNonce),
    TxOutput(Id<Transaction>, u32),
    // TODO: Block reward?

    // Note that orders v1 are not needed here, because:
    // 1) Since they don't use nonces, they don't create dependencies the way other account-based
    //    inputs do.
    // 2) We could introduce a pseudo-dependency, e.g. in the form of an `enum { Fillable, Freezable, Concludable }`
    //    (we'd have to differentiate between dependencies that a tx requires vs those that it consumes,
    //    so e.g. a `FreezeOrder` input would require `Freezable` but consume both `Freezable` and `Fillable`).
    //    However, this doesn't seem to be useful because currently, with RBF disabled, `TxDependency`
    //    itself has limited use:
    //    a) It's used to check for conflicts (`check_mempool_policy` calls `conflicting_tx_ids`
    //       and returns `MempoolConflictError::Irreplacable` if any), but this check doesn't seem
    //       to be really needed, because a conflicting tx will always be rejected by the tx verifier
    //       anyway (also, since the tx verifier call happens first, it doesn't seem that this
    //       `Irreplacable` result is possible at all, unless it's a bug).
    //       Though technically, we could use the pseudo-dependency as an optimization, to avoid calling
    //       the tx verifier when we know it'll fail anyway.
    //    b) The orphan pool uses a TxDependency map to check whether tx's dependencies could have become
    //       satisfied. The pseudo-dependency won't be useful here at all.
    //    (Also note that even when RBF is finally implemented, RBFing an order-related tx will probably
    //    be based on re-using one of the UTXOs of the original tx, so tracking order inputs will probably
    //    not be needed anyway).
    // TODO: return to this when enabling RBF.
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
            AccountSpending::DelegationBalance(delegation_id, _) => {
                Self::DelegationAccount(*delegation_id, nonce)
            }
        }
    }

    fn from_account_cmd(cmd: &AccountCommand, nonce: AccountNonce) -> Self {
        match cmd {
            AccountCommand::MintTokens(token_id, _)
            | AccountCommand::UnmintTokens(token_id)
            | AccountCommand::LockTokenSupply(token_id)
            | AccountCommand::FreezeToken(token_id, _)
            | AccountCommand::UnfreezeToken(token_id)
            | AccountCommand::ChangeTokenMetadataUri(token_id, _)
            | AccountCommand::ChangeTokenAuthority(token_id, _) => {
                Self::TokenSupplyAccount(*token_id, nonce)
            }
            AccountCommand::ConcludeOrder(order_id) | AccountCommand::FillOrder(order_id, _, _) => {
                Self::OrderV0Account(*order_id, nonce)
            }
        }
    }

    fn from_input_requires(input: &TxInput) -> Option<Self> {
        // TODO: the "nonce().decrement().map()" calls below don't seem to be correct, because
        // returning None for account-based inputs with zero nonce means that such inputs will
        // never be considered as conflicting. Perhaps we should store `Option<AccountNonce>`
        // inside TxDependency's variants instead.
        // (Note that this issue doesn't seem to have a noticeable impact at this moment,
        // with disabled RBF).
        match input {
            TxInput::Utxo(utxo) => Self::from_utxo(utxo),
            TxInput::Account(acct) => {
                acct.nonce().decrement().map(|nonce| Self::from_account(acct.account(), nonce))
            }
            TxInput::AccountCommand(nonce, op) => {
                nonce.decrement().map(|nonce| Self::from_account_cmd(op, nonce))
            }
            TxInput::OrderAccountCommand(_) => None,
        }
    }

    fn from_input_provides(input: &TxInput) -> Option<Self> {
        match input {
            TxInput::Utxo(_) => None,
            TxInput::Account(acct) => Some(Self::from_account(acct.account(), acct.nonce())),
            TxInput::AccountCommand(nonce, op) => Some(Self::from_account_cmd(op, *nonce)),
            TxInput::OrderAccountCommand(_) => None,
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
