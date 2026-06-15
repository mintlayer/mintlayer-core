// Copyright (c) 2023-2026 RBB S.r.l
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

use mempool_types::tx_origin::IsOrigin;
use smallvec::SmallVec;
use strum::IntoEnumIterator as _;

use common::{
    chain::{
        AccountCommand, AccountNonce, AccountSpending, DelegationId, IdCreationError,
        TokenIdGenerationVersion, Transaction, TxInput, TxOutput, make_token_id_with_version,
        tokens::TokenId,
    },
    primitives::Id,
};

use crate::pool::entry::TxEntry;

/// A dependency that is provided by a transaction.
///
/// Note: for accounts that have a nonce, the stored nonce is the one that will be available
/// for consumption by other txs (i.e. it's the nonce from the providing tx plus one).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxProvidedDependency {
    TxOutput(Id<Transaction>, u32),
    DelegationAccount(DelegationId, AccountNonce),
    TokenAccount(TokenId, AccountNonce),
    TokenCreation(TokenId),
}

// FIXME TxProvidedNonUtxoDependency?

impl TxProvidedDependency {
    pub fn from_tx<O: IsOrigin>(entry: &TxEntry<O>) -> impl Iterator<Item = Self> {
        let from_inputs = entry.transaction().inputs().iter().filter_map(Self::from_input);

        let from_outputs =
            entry
                .transaction()
                .outputs()
                .iter()
                .enumerate()
                .filter_map(|(output_idx, output)| {
                    Self::from_output(
                        output,
                        output_idx as u32,
                        entry.tx_id(),
                        entry.transaction().inputs(),
                    )
                });

        from_inputs.chain(from_outputs)
    }

    fn from_input(input: &TxInput) -> Option<Self> {
        match input {
            TxInput::Utxo(_) => None,
            TxInput::Account(acct) => Self::from_account(acct.account(), acct.nonce().increment()?),
            TxInput::AccountCommand(nonce, op) => Self::from_account_cmd(op, nonce.increment()?),
            TxInput::OrderAccountCommand(_) => None,
        }
    }

    fn from_output(
        output: &TxOutput,
        output_idx: u32,
        tx_id: &Id<Transaction>,
        inputs: &[TxInput],
    ) -> Option<Self> {
        match output {
            TxOutput::IssueFungibleToken(_) => {
                // This will produce a compilation failure if TokenIdGenerationVersion gets a new
                // variant (shouldn't happen, but just in case).
                for ver in TokenIdGenerationVersion::iter() {
                    match ver {
                        TokenIdGenerationVersion::V0 | TokenIdGenerationVersion::V1 => {}
                    }
                }

                // FIXME return Result?
                let token_id =
                    make_token_id_with_version(TokenIdGenerationVersion::V1, inputs).ok()?;

                Some(Self::TokenCreation(token_id))
            }

            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::Htlc(_, _)
            | TxOutput::CreateStakePool(_, _)
            | TxOutput::ProduceBlockFromStake(_, _) => Some(Self::TxOutput(*tx_id, output_idx)),
            // These outputs are not spendable
            | TxOutput::Burn(_)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::DataDeposit(_)
            | TxOutput::CreateOrder(_) => None,
        }
    }

    fn from_account(account: &AccountSpending, nonce: AccountNonce) -> Option<Self> {
        match account {
            AccountSpending::DelegationBalance(delegation_id, _) => {
                Some(Self::DelegationAccount(*delegation_id, nonce))
            }
        }
    }

    fn from_account_cmd(cmd: &AccountCommand, nonce: AccountNonce) -> Option<Self> {
        match cmd {
            AccountCommand::MintTokens(token_id, _)
            | AccountCommand::UnmintTokens(token_id)
            | AccountCommand::LockTokenSupply(token_id)
            | AccountCommand::FreezeToken(token_id, _)
            | AccountCommand::UnfreezeToken(token_id)
            | AccountCommand::ChangeTokenMetadataUri(token_id, _)
            | AccountCommand::ChangeTokenAuthority(token_id, _) => {
                Some(Self::TokenAccount(*token_id, nonce))
            }
            // Orders V0 are not tracked
            AccountCommand::ConcludeOrder(_) | AccountCommand::FillOrder(_, _, _) => None,
        }
    }

    pub fn into_requirement(self) -> TxRequiredDependency {
        // Note: account nonces are put into TxRequiredDependency as is, this is because
        // TxProvidedDependency's nonce is the providing tx's nonce plus one, which is what
        // the requiring tx consumes.
        match self {
            Self::TxOutput(tx_id, output_idx) => TxRequiredDependency::TxOutput(tx_id, output_idx),
            Self::DelegationAccount(delg_id, nonce) => {
                TxRequiredDependency::DelegationAccount(delg_id, nonce)
            }
            Self::TokenAccount(token_id, nonce) => {
                TxRequiredDependency::TokenAccount(token_id, nonce)
            }
            Self::TokenCreation(token_id) => TxRequiredDependency::TokenCreation(token_id),
        }
    }

    // FIXME consistency tests
    pub fn from_requirement(req: TxRequiredDependency) -> Self {
        // Note: account nonces are put into TxRequiredDependency as is, this is because
        // TxProvidedDependency's nonce is the providing tx's nonce plus one, which is what
        // the requiring tx consumes.
        match req {
            TxRequiredDependency::TxOutput(tx_id, output_idx) => Self::TxOutput(tx_id, output_idx),
            TxRequiredDependency::DelegationAccount(delg_id, nonce) => {
                Self::DelegationAccount(delg_id, nonce)
            }
            TxRequiredDependency::TokenAccount(token_id, nonce) => {
                Self::TokenAccount(token_id, nonce)
            }
            TxRequiredDependency::TokenCreation(token_id) => Self::TokenCreation(token_id),
        }
    }
}

/// A dependency that is required by a transaction.
///
/// Note:
/// * structurally this is identical to `TxProvidedDependency`. A distinct type is used
///   for logical separation;
/// * for accounts that have a nonce, the stored nonce is the one that is consumed by the
///   requiring tx.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxRequiredDependency {
    TxOutput(Id<Transaction>, u32),
    DelegationAccount(DelegationId, AccountNonce),
    TokenAccount(TokenId, AccountNonce),
    TokenCreation(TokenId),
}

impl TxRequiredDependency {
    pub fn from_tx<O: IsOrigin>(entry: &TxEntry<O>) -> impl Iterator<Item = Self> {
        entry.transaction().inputs().iter().flat_map(Self::from_input)
    }

    fn from_input(input: &TxInput) -> impl Iterator<Item = Self> {
        // Use SmallVec to avoid allocations (we'll be producing at most 2 values here).
        let mut result = SmallVec::<[_; 2]>::new();

        match input {
            TxInput::Utxo(outpoint) => {
                if let Some(tx_id) = outpoint.source_id().get_tx_id() {
                    result.push(Self::TxOutput(*tx_id, outpoint.output_index()));
                }
            }
            TxInput::Account(acct) => match acct.account() {
                AccountSpending::DelegationBalance(delegation_id, _) => {
                    result.push(Self::DelegationAccount(*delegation_id, acct.nonce()));
                }
            },
            TxInput::AccountCommand(nonce, cmd) => {
                match cmd {
                    AccountCommand::MintTokens(token_id, _)
                    | AccountCommand::UnmintTokens(token_id)
                    | AccountCommand::LockTokenSupply(token_id)
                    | AccountCommand::FreezeToken(token_id, _)
                    | AccountCommand::UnfreezeToken(token_id)
                    | AccountCommand::ChangeTokenMetadataUri(token_id, _)
                    | AccountCommand::ChangeTokenAuthority(token_id, _) => {
                        result.push(Self::TokenAccount(*token_id, *nonce));

                        if nonce.value() == 0 {
                            result.push(Self::TokenCreation(*token_id));
                        }
                    }
                    // Orders V0 are not tracked
                    AccountCommand::ConcludeOrder(_) | AccountCommand::FillOrder(_, _, _) => {}
                }
            }
            TxInput::OrderAccountCommand(_) => {}
        }

        result.into_iter()
    }

    pub fn into_consumed(self) -> Option<TxConsumedDependency> {
        match self {
            Self::TxOutput(tx_id, output_idx) => {
                Some(TxConsumedDependency::TxOutput(tx_id, output_idx))
            }
            Self::DelegationAccount(delg_id, nonce) => {
                Some(TxConsumedDependency::DelegationAccount(delg_id, nonce))
            }
            Self::TokenAccount(token_id, nonce) => {
                Some(TxConsumedDependency::TokenAccount(token_id, nonce))
            }
            Self::TokenCreation(_) => None,
        }
    }
}

/// A dependency that is consumed by a transaction.
///
/// This is a subset of `TxRequiredDependency`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxConsumedDependency {
    TxOutput(Id<Transaction>, u32),
    DelegationAccount(DelegationId, AccountNonce),
    TokenAccount(TokenId, AccountNonce),
}

// FIXME
#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum DependencyError {
    #[error(transparent)]
    IdCreationError(#[from] IdCreationError),
}
