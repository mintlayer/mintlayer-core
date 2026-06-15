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
        OrderAccountCommand, OrderId, PoolId, TokenIdGenerationVersion, Transaction, TxInput,
        TxOutput, make_delegation_id, make_order_id, make_token_id_with_version, tokens::TokenId,
    },
    primitives::Id,
};
use utils::debug_panic_or_log;

use crate::pool::entry::TxEntry;

/// A dependency that is required by a transaction.
///
/// Note:
/// * For accounts that have a nonce, the stored nonce is the one that is consumed by the
///   requiring tx.
/// * The deprecated order V0 commands are ignored.
/// * We avoid creating pseudo-dependencies between transactions (such as putting all order fills
///   before the corresponding freeze and the freeze before the conclusion, or putting all delegations
///   before delegation withdrawals for the given delegation id); this would be redundant and it
///   would contradict the mempool's goal of selecting the most lucrative transactions for inclusion
///   in a block (also note that putting all fills before freeze/conclude would also be exploitable -
///   an attacker would be able to postpone freezing/conclusion of an order by flooding the mempool
///   with fills).
/// * For some of the dependencies, there is not much sense in tracking them because having both
///   txs in the mempool at the same time would be a pathological case. E.g. delegation creation
///   and delegation withdrawal don't make sense together. But we do track them, for completeness.
/// * The dependency of order commands on order creation is not redundant, at least in the
///   "freeze -> order creation" case - if an order has been created by mistake, the creator may
///   want to freeze it immediately (in the same block).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, strum::EnumDiscriminants)]
#[strum_discriminants(name(TxRequiredDependencyTag), derive(strum::EnumIter))]
pub enum TxRequiredDependency {
    TxOutput(Id<Transaction>, u32),
    PoolCreation(PoolId),
    DelegationCreation(DelegationId),
    DelegationSpending(DelegationId, AccountNonce),
    TokenCreation(TokenId),
    TokenAccountManagement(TokenId, AccountNonce),
    OrderCreation(OrderId),
}

impl TxRequiredDependency {
    pub fn from_tx<O: IsOrigin>(entry: &TxEntry<O>) -> impl Iterator<Item = Self> {
        let from_inputs = entry.transaction().inputs().iter().flat_map(Self::from_input);

        let from_outputs = entry.transaction().outputs().iter().filter_map(Self::from_output);

        from_inputs.chain(from_outputs)
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
                    result.push(Self::DelegationSpending(*delegation_id, acct.nonce()));

                    if acct.nonce().value() == 0 {
                        result.push(Self::DelegationCreation(*delegation_id));
                    }
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
                        result.push(Self::TokenAccountManagement(*token_id, *nonce));

                        if nonce.value() == 0 {
                            result.push(Self::TokenCreation(*token_id));
                        }
                    }
                    // Orders V0 are not tracked
                    AccountCommand::ConcludeOrder(_) | AccountCommand::FillOrder(_, _, _) => {}
                }
            }
            TxInput::OrderAccountCommand(cmd) => {
                let order_id = match cmd {
                    OrderAccountCommand::FillOrder(id, _)
                    | OrderAccountCommand::FreezeOrder(id)
                    | OrderAccountCommand::ConcludeOrder(id) => id,
                };

                result.push(Self::OrderCreation(*order_id));
            }
        }

        result.into_iter()
    }

    fn from_output(output: &TxOutput) -> Option<Self> {
        match output {
            TxOutput::CreateDelegationId(_, pool_id) => Some(Self::PoolCreation(*pool_id)),
            TxOutput::DelegateStaking(_, delegation_id) => {
                Some(Self::DelegationCreation(*delegation_id))
            }

            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::Burn(_)
            | TxOutput::CreateStakePool(_, _)
            | TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::DataDeposit(_)
            | TxOutput::Htlc(_, _)
            | TxOutput::CreateOrder(_) => None,
        }
    }

    pub fn into_consumed(self) -> Option<TxConsumedDependency> {
        match self {
            Self::TxOutput(tx_id, output_idx) => {
                Some(TxConsumedDependency::TxOutput(tx_id, output_idx))
            }
            Self::DelegationSpending(delegation_id, nonce) => Some(
                TxConsumedDependency::DelegationSpending(delegation_id, nonce),
            ),
            Self::TokenAccountManagement(token_id, nonce) => Some(
                TxConsumedDependency::TokenAccountManagement(token_id, nonce),
            ),
            Self::PoolCreation(_)
            | Self::DelegationCreation(_)
            | Self::TokenCreation(_)
            | Self::OrderCreation(_) => None,
        }
    }
}

/// A dependency that is consumed by a transaction.
///
/// This is a subset of `TxRequiredDependency`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxConsumedDependency {
    TxOutput(Id<Transaction>, u32),
    DelegationSpending(DelegationId, AccountNonce),
    TokenAccountManagement(TokenId, AccountNonce),
}

/// A dependency that is provided by a transaction, not counting UTXO-based dependencies.
///
/// Note: for accounts that have a nonce, the stored nonce is the one that will be available
/// for consumption by other txs (i.e. it's the nonce from the providing tx plus one).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxProvidedNonUtxoDependency {
    PoolCreation(PoolId),
    DelegationCreation(DelegationId),
    DelegationSpending(DelegationId, AccountNonce),
    TokenCreation(TokenId),
    TokenAccountManagement(TokenId, AccountNonce),
    OrderCreation(OrderId),
}

impl TxProvidedNonUtxoDependency {
    pub fn from_tx<O: IsOrigin>(entry: &TxEntry<O>) -> impl Iterator<Item = Self> {
        let from_inputs = entry.transaction().inputs().iter().filter_map(Self::from_input);

        let from_outputs = entry.transaction().outputs().iter().filter_map(|output| {
            Self::from_output(output, entry.tx_id(), entry.transaction().inputs())
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

    fn from_output(output: &TxOutput, tx_id: &Id<Transaction>, inputs: &[TxInput]) -> Option<Self> {
        match output {
            TxOutput::IssueFungibleToken(_) => {
                // This will produce a compilation failure if TokenIdGenerationVersion gets a new
                // variant (shouldn't happen, but just in case).
                for ver in TokenIdGenerationVersion::iter() {
                    match ver {
                        TokenIdGenerationVersion::V0 | TokenIdGenerationVersion::V1 => {}
                    }
                }

                // Note: an error shouldn't be possible here for a valid tx.
                match make_token_id_with_version(TokenIdGenerationVersion::V1, inputs) {
                    Ok(token_id) => Some(Self::TokenCreation(token_id)),
                    Err(err) => {
                        debug_panic_or_log!(
                            "Error creating token id from inputs of tx {tx_id:x}: {err}"
                        );
                        None
                    }
                }
            }

            | TxOutput::CreateDelegationId(_, _) => {
                // Note: an error shouldn't be possible here for a valid tx.
                match make_delegation_id(inputs) {
                    Ok(delegation_id) => Some(Self::DelegationCreation(delegation_id)),
                    Err(err) => {
                        debug_panic_or_log!(
                            "Error creating delegation id from inputs of tx {tx_id:x}: {err}"
                        );
                        None
                    }
                }
            }

            TxOutput::CreateStakePool(pool_id, _) => Some(Self::PoolCreation(*pool_id)),

            TxOutput::CreateOrder(_) => {
                // Note: an error shouldn't be possible here for a valid tx.
                match make_order_id(inputs) {
                    Ok(order_id) => Some(Self::OrderCreation(order_id)),
                    Err(err) => {
                        debug_panic_or_log!(
                            "Error creating order id from inputs of tx {tx_id:x}: {err}"
                        );
                        None
                    }
                }
            }

            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::Htlc(_, _)
            | TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::Burn(_)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::DataDeposit(_) => None,
        }
    }

    fn from_account(account: &AccountSpending, nonce: AccountNonce) -> Option<Self> {
        match account {
            AccountSpending::DelegationBalance(delegation_id, _) => {
                Some(Self::DelegationSpending(*delegation_id, nonce))
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
                Some(Self::TokenAccountManagement(*token_id, nonce))
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
            Self::PoolCreation(pool_id) => TxRequiredDependency::PoolCreation(pool_id),
            Self::DelegationCreation(delegation_id) => {
                TxRequiredDependency::DelegationCreation(delegation_id)
            }
            Self::DelegationSpending(delegation_id, nonce) => {
                TxRequiredDependency::DelegationSpending(delegation_id, nonce)
            }
            Self::TokenCreation(token_id) => TxRequiredDependency::TokenCreation(token_id),
            Self::TokenAccountManagement(token_id, nonce) => {
                TxRequiredDependency::TokenAccountManagement(token_id, nonce)
            }
            Self::OrderCreation(order_id) => TxRequiredDependency::OrderCreation(order_id),
        }
    }

    pub fn from_requirement(req: TxRequiredDependency) -> Option<Self> {
        // Note: account nonces are put into TxRequiredDependency as is, this is because
        // TxProvidedDependency's nonce is the providing tx's nonce plus one, which is what
        // the requiring tx consumes.
        match req {
            TxRequiredDependency::TxOutput(_, _) => None,
            TxRequiredDependency::PoolCreation(pool_id) => Some(Self::PoolCreation(pool_id)),
            TxRequiredDependency::DelegationCreation(delegation_id) => {
                Some(Self::DelegationCreation(delegation_id))
            }
            TxRequiredDependency::DelegationSpending(delegation_id, nonce) => {
                Some(Self::DelegationSpending(delegation_id, nonce))
            }
            TxRequiredDependency::TokenCreation(token_id) => Some(Self::TokenCreation(token_id)),
            TxRequiredDependency::TokenAccountManagement(token_id, nonce) => {
                Some(Self::TokenAccountManagement(token_id, nonce))
            }
            TxRequiredDependency::OrderCreation(order_id) => Some(Self::OrderCreation(order_id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use randomness::RngExt;
    use test_utils::random::{Seed, make_seedable_rng};

    use super::*;

    #[rstest]
    #[case(Seed::from_entropy())]
    #[trace]
    fn provided_required_dep_conversion(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        for tag in TxRequiredDependencyTag::iter() {
            match tag {
                TxRequiredDependencyTag::TxOutput => {
                    let required =
                        TxRequiredDependency::TxOutput(Id::random_using(&mut rng), rng.random());
                    let provided = TxProvidedNonUtxoDependency::from_requirement(required);
                    assert!(provided.is_none());
                }
                TxRequiredDependencyTag::PoolCreation => {
                    let pool_id = Id::random_using(&mut rng);
                    let required = TxRequiredDependency::PoolCreation(pool_id);
                    let provided =
                        TxProvidedNonUtxoDependency::from_requirement(required.clone()).unwrap();
                    assert_eq!(provided, TxProvidedNonUtxoDependency::PoolCreation(pool_id));
                    let required_conv = provided.into_requirement();
                    assert_eq!(required_conv, required);
                }
                TxRequiredDependencyTag::DelegationCreation => {
                    let delegation_id = Id::random_using(&mut rng);
                    let required = TxRequiredDependency::DelegationCreation(delegation_id);
                    let provided =
                        TxProvidedNonUtxoDependency::from_requirement(required.clone()).unwrap();
                    assert_eq!(
                        provided,
                        TxProvidedNonUtxoDependency::DelegationCreation(delegation_id)
                    );
                    let required_conv = provided.into_requirement();
                    assert_eq!(required_conv, required);
                }
                TxRequiredDependencyTag::DelegationSpending => {
                    let delegation_id = Id::random_using(&mut rng);
                    let nonce = AccountNonce::new(rng.random());
                    let required = TxRequiredDependency::DelegationSpending(delegation_id, nonce);
                    let provided =
                        TxProvidedNonUtxoDependency::from_requirement(required.clone()).unwrap();
                    assert_eq!(
                        provided,
                        TxProvidedNonUtxoDependency::DelegationSpending(delegation_id, nonce)
                    );
                    let required_conv = provided.into_requirement();
                    assert_eq!(required_conv, required);
                }
                TxRequiredDependencyTag::TokenCreation => {
                    let token_id = Id::random_using(&mut rng);
                    let required = TxRequiredDependency::TokenCreation(token_id);
                    let provided =
                        TxProvidedNonUtxoDependency::from_requirement(required.clone()).unwrap();
                    assert_eq!(
                        provided,
                        TxProvidedNonUtxoDependency::TokenCreation(token_id)
                    );
                    let required_conv = provided.into_requirement();
                    assert_eq!(required_conv, required);
                }
                TxRequiredDependencyTag::TokenAccountManagement => {
                    let token_id = Id::random_using(&mut rng);
                    let nonce = AccountNonce::new(rng.random());
                    let required = TxRequiredDependency::TokenAccountManagement(token_id, nonce);
                    let provided =
                        TxProvidedNonUtxoDependency::from_requirement(required.clone()).unwrap();
                    assert_eq!(
                        provided,
                        TxProvidedNonUtxoDependency::TokenAccountManagement(token_id, nonce)
                    );
                    let required_conv = provided.into_requirement();
                    assert_eq!(required_conv, required);
                }
                TxRequiredDependencyTag::OrderCreation => {
                    let order_id = Id::random_using(&mut rng);
                    let required = TxRequiredDependency::OrderCreation(order_id);
                    let provided =
                        TxProvidedNonUtxoDependency::from_requirement(required.clone()).unwrap();
                    assert_eq!(
                        provided,
                        TxProvidedNonUtxoDependency::OrderCreation(order_id)
                    );
                    let required_conv = provided.into_requirement();
                    assert_eq!(required_conv, required);
                }
            }
        }
    }
}
