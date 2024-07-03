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

use common::chain::{
    block::BlockRewardTransactable,
    signature::{
        inputsig::{
            authorize_hashed_timelock_contract_spend::AuthorizedHashedTimelockContractSpend,
            standard_signature::StandardInputSignature, InputWitness,
        },
        DestinationSigError,
    },
    tokens::TokenId,
    AccountCommand, AccountOutPoint, AccountSpending, DelegationId, Destination, OrderId, PoolId,
    SignedTransaction, TxOutput, UtxoOutPoint,
};
use pos_accounting::PoolData;
use utxo::Utxo;

use crate::{script::HashChallenge, WitnessScript};

/// An error that can happen during translation of an input to a script
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum TranslationError {
    #[error("Attempt to spend an unspendable output")]
    Unspendable,

    #[error("Illegal account spend")]
    IllegalAccountSpend,

    #[error("Illegal output spend")]
    IllegalOutputSpend,

    #[error(transparent)]
    PoSAccounting(#[from] pos_accounting::Error),

    #[error(transparent)]
    TokensAccounting(#[from] tokens_accounting::Error),

    #[error(transparent)]
    OrdersAccounting(#[from] orders_accounting::Error),

    #[error(transparent)]
    SignatureError(#[from] DestinationSigError),

    #[error("Stake pool {0} does not exist")]
    PoolNotFound(PoolId),

    #[error("Delegation {0} does not exist")]
    DelegationNotFound(DelegationId),

    #[error("Token with id {0} does not exist")]
    TokenNotFound(TokenId),

    #[error("Order with id {0} does not exist")]
    OrderNotFound(OrderId),
}

/// Contextual information about given input
pub enum InputInfo<'a> {
    Utxo {
        outpoint: &'a UtxoOutPoint,
        utxo: Utxo,
    },
    Account {
        outpoint: &'a AccountOutPoint,
    },
    AccountCommand {
        command: &'a AccountCommand,
    },
}

impl InputInfo<'_> {
    pub fn as_utxo_output(&self) -> Option<&TxOutput> {
        match self {
            InputInfo::Utxo { outpoint: _, utxo } => Some(utxo.output()),
            InputInfo::Account { .. } | InputInfo::AccountCommand { .. } => None,
        }
    }
}

pub trait InputInfoProvider {
    fn input_info(&self) -> &InputInfo;
    fn witness(&self) -> &InputWitness;
}

/// Provides information necessary to translate an input to a script.
pub trait SignatureInfoProvider: InputInfoProvider {
    fn get_pool_decommission_destination(
        &self,
        pool_id: &PoolId,
    ) -> Result<Option<Destination>, pos_accounting::Error>;

    fn get_delegation_spend_destination(
        &self,
        delegation_id: &DelegationId,
    ) -> Result<Option<Destination>, pos_accounting::Error>;

    fn get_tokens_authority(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<Destination>, tokens_accounting::Error>;

    fn get_orders_conclude_destination(
        &self,
        order_id: &OrderId,
    ) -> Result<Option<Destination>, orders_accounting::Error>;
}

pub trait TranslateInput<C> {
    /// Translate transaction input to script.
    fn translate_input(ctx: &C) -> Result<WitnessScript, TranslationError>;
}

impl<C: SignatureInfoProvider> TranslateInput<C> for SignedTransaction {
    fn translate_input(ctx: &C) -> Result<WitnessScript, TranslationError> {
        let checksig =
            |dest: &Destination| WitnessScript::signature(dest.clone(), ctx.witness().clone());

        match ctx.input_info() {
            InputInfo::Utxo { outpoint: _, utxo } => match utxo.output() {
                TxOutput::Transfer(_val, dest) => Ok(checksig(dest)),
                TxOutput::LockThenTransfer(_val, dest, timelock) => {
                    Ok(WitnessScript::satisfied_conjunction([
                        WitnessScript::timelock(*timelock),
                        checksig(dest),
                    ]))
                }
                TxOutput::CreateStakePool(_pool_id, pool_data) => {
                    Ok(checksig(pool_data.decommission_key()))
                }
                TxOutput::ProduceBlockFromStake(_, pool_id) => {
                    let dest = ctx
                        .get_pool_decommission_destination(pool_id)?
                        .ok_or(TranslationError::PoolNotFound(*pool_id))?;
                    Ok(checksig(&dest))
                }
                TxOutput::Htlc(_, htlc) => {
                    let script = match ctx.witness() {
                        InputWitness::NoSignature(_) => {
                            return Err(TranslationError::SignatureError(
                                DestinationSigError::SignatureNotFound,
                            ))
                        }
                        InputWitness::Standard(sig) => {
                            let htlc_spend = AuthorizedHashedTimelockContractSpend::from_data(
                                sig.raw_signature(),
                            )?;
                            match htlc_spend {
                                AuthorizedHashedTimelockContractSpend::Secret(
                                    secret,
                                    raw_signature,
                                ) => WitnessScript::satisfied_conjunction([
                                    WitnessScript::hashlock(
                                        HashChallenge::Hash160(htlc.secret_hash.to_fixed_bytes()),
                                        secret.consume(),
                                    ),
                                    WitnessScript::signature(
                                        htlc.spend_key.clone(),
                                        InputWitness::Standard(StandardInputSignature::new(
                                            sig.sighash_type(),
                                            raw_signature,
                                        )),
                                    ),
                                ]),
                                AuthorizedHashedTimelockContractSpend::Multisig(raw_signature) => {
                                    WitnessScript::satisfied_conjunction([
                                        WitnessScript::timelock(htlc.refund_timelock),
                                        WitnessScript::signature(
                                            htlc.refund_key.clone(),
                                            InputWitness::Standard(StandardInputSignature::new(
                                                sig.sighash_type(),
                                                raw_signature,
                                            )),
                                        ),
                                    ])
                                }
                            }
                        }
                    };
                    Ok(script)
                }
                TxOutput::IssueNft(_id, _issuance, dest) => Ok(checksig(dest)),
                TxOutput::DelegateStaking(_amount, _deleg_id) => Err(TranslationError::Unspendable),
                TxOutput::CreateDelegationId(_dest, _pool_id) => Err(TranslationError::Unspendable),
                TxOutput::IssueFungibleToken(_issuance) => Err(TranslationError::Unspendable),
                TxOutput::Burn(_val) => Err(TranslationError::Unspendable),
                TxOutput::DataDeposit(_data) => Err(TranslationError::Unspendable),
                TxOutput::AnyoneCanTake(_) => Err(TranslationError::Unspendable),
            },
            InputInfo::Account { outpoint } => match outpoint.account() {
                AccountSpending::DelegationBalance(delegation_id, _amount) => {
                    let dest = ctx
                        .get_delegation_spend_destination(delegation_id)?
                        .ok_or(TranslationError::DelegationNotFound(*delegation_id))?;
                    Ok(checksig(&dest))
                }
            },
            InputInfo::AccountCommand { command } => match command {
                AccountCommand::MintTokens(token_id, _)
                | AccountCommand::UnmintTokens(token_id)
                | AccountCommand::LockTokenSupply(token_id)
                | AccountCommand::FreezeToken(token_id, _)
                | AccountCommand::UnfreezeToken(token_id)
                | AccountCommand::ChangeTokenAuthority(token_id, _) => {
                    let dest = ctx
                        .get_tokens_authority(token_id)?
                        .ok_or(TranslationError::TokenNotFound(*token_id))?;
                    Ok(checksig(&dest))
                }
                AccountCommand::ConcludeOrder(order_id) => {
                    let dest = ctx
                        .get_orders_conclude_destination(order_id)?
                        .ok_or(TranslationError::OrderNotFound(*order_id))?;
                    Ok(checksig(&dest))
                }
                AccountCommand::FillOrder(_, _, _) => Ok(WitnessScript::TRUE),
            },
        }
    }
}

impl<C: SignatureInfoProvider> TranslateInput<C> for BlockRewardTransactable<'_> {
    fn translate_input(ctx: &C) -> Result<WitnessScript, TranslationError> {
        let checksig =
            |dest: &Destination| WitnessScript::signature(dest.clone(), ctx.witness().clone());
        match ctx.input_info() {
            InputInfo::Utxo { outpoint: _, utxo } => {
                match utxo.output() {
                    TxOutput::Transfer(_, _)
                    | TxOutput::LockThenTransfer(_, _, _)
                    | TxOutput::IssueNft(_, _, _)
                    | TxOutput::Htlc(_, _) => Err(TranslationError::IllegalOutputSpend),
                    TxOutput::CreateDelegationId(_, _)
                    | TxOutput::Burn(_)
                    | TxOutput::DataDeposit(_)
                    | TxOutput::DelegateStaking(_, _)
                    | TxOutput::IssueFungibleToken(_)
                    | TxOutput::AnyoneCanTake(_) => Err(TranslationError::Unspendable),

                    TxOutput::ProduceBlockFromStake(d, _) => {
                        // Spending an output of a block creation output is only allowed to
                        // create another block, given that this is a block reward.
                        Ok(checksig(d))
                    }
                    TxOutput::CreateStakePool(_, pool_data) => {
                        // Spending an output of a pool creation output is only allowed when
                        // creating a block (given it's in a block reward; otherwise it should
                        // be a transaction for decommissioning the pool), hence the staker key
                        // is checked.
                        Ok(checksig(pool_data.staker()))
                    }
                }
            }
            InputInfo::Account { .. } | InputInfo::AccountCommand { .. } => {
                Err(TranslationError::IllegalAccountSpend)
            }
        }
    }
}

pub struct TimelockOnly;

impl<C: InputInfoProvider> TranslateInput<C> for TimelockOnly {
    fn translate_input(ctx: &C) -> Result<WitnessScript, TranslationError> {
        match ctx.input_info() {
            InputInfo::Utxo { outpoint: _, utxo } => match utxo.output() {
                TxOutput::LockThenTransfer(_val, _dest, timelock) => {
                    Ok(WitnessScript::timelock(*timelock))
                }
                TxOutput::Htlc(_, htlc) => match ctx.witness() {
                    InputWitness::NoSignature(_) => Err(TranslationError::SignatureError(
                        DestinationSigError::SignatureNotFound,
                    )),
                    InputWitness::Standard(sig) => {
                        let htlc_spend =
                            AuthorizedHashedTimelockContractSpend::from_data(sig.raw_signature())?;
                        match htlc_spend {
                            AuthorizedHashedTimelockContractSpend::Secret(_, _) => {
                                Ok(WitnessScript::TRUE)
                            }
                            AuthorizedHashedTimelockContractSpend::Multisig(_) => {
                                Ok(WitnessScript::timelock(htlc.refund_timelock))
                            }
                        }
                    }
                },
                TxOutput::Transfer(_, _)
                | TxOutput::CreateStakePool(_, _)
                | TxOutput::ProduceBlockFromStake(_, _)
                | TxOutput::IssueNft(_, _, _) => Ok(WitnessScript::TRUE),
                TxOutput::CreateDelegationId(_, _)
                | TxOutput::IssueFungibleToken(_)
                | TxOutput::DelegateStaking(_, _)
                | TxOutput::Burn(_)
                | TxOutput::DataDeposit(_)
                | TxOutput::AnyoneCanTake(_) => Err(TranslationError::Unspendable),
            },
            InputInfo::Account { outpoint } => match outpoint.account() {
                AccountSpending::DelegationBalance(_deleg_id, _amt) => Ok(WitnessScript::TRUE),
            },
            InputInfo::AccountCommand { command } => match command {
                AccountCommand::MintTokens(_token_id, _)
                | AccountCommand::UnmintTokens(_token_id)
                | AccountCommand::LockTokenSupply(_token_id)
                | AccountCommand::FreezeToken(_token_id, _)
                | AccountCommand::UnfreezeToken(_token_id)
                | AccountCommand::ChangeTokenAuthority(_token_id, _) => Ok(WitnessScript::TRUE),
                AccountCommand::ConcludeOrder(_) | AccountCommand::FillOrder(_, _, _) => {
                    Ok(WitnessScript::TRUE)
                }
            },
        }
    }
}

// FIXME: prevent from using with block reward
pub struct SignatureOnly;

impl<C: SignatureInfoProvider> TranslateInput<C> for SignatureOnly {
    fn translate_input(ctx: &C) -> Result<WitnessScript, TranslationError> {
        let checksig =
            |dest: &Destination| WitnessScript::signature(dest.clone(), ctx.witness().clone());

        match ctx.input_info() {
            InputInfo::Utxo { outpoint: _, utxo } => match utxo.output() {
                TxOutput::Transfer(_val, dest) | TxOutput::LockThenTransfer(_val, dest, _) => {
                    Ok(checksig(dest))
                }
                TxOutput::CreateStakePool(_pool_id, pool_data) => {
                    Ok(checksig(pool_data.decommission_key()))
                }
                TxOutput::ProduceBlockFromStake(_dest, pool_id) => {
                    let dest = ctx
                        .get_pool_decommission_destination(pool_id)?
                        .ok_or(TranslationError::PoolNotFound(*pool_id))?;
                    Ok(checksig(&dest))
                }
                TxOutput::Htlc(_, htlc) => {
                    let script = match ctx.witness() {
                        InputWitness::NoSignature(_) => {
                            return Err(TranslationError::SignatureError(
                                DestinationSigError::SignatureNotFound,
                            ))
                        }
                        InputWitness::Standard(sig) => {
                            let htlc_spend = AuthorizedHashedTimelockContractSpend::from_data(
                                sig.raw_signature(),
                            )?;
                            match htlc_spend {
                                AuthorizedHashedTimelockContractSpend::Secret(_, raw_signature) => {
                                    WitnessScript::signature(
                                        htlc.spend_key.clone(),
                                        InputWitness::Standard(StandardInputSignature::new(
                                            sig.sighash_type(),
                                            raw_signature,
                                        )),
                                    )
                                }
                                AuthorizedHashedTimelockContractSpend::Multisig(raw_signature) => {
                                    WitnessScript::signature(
                                        htlc.refund_key.clone(),
                                        InputWitness::Standard(StandardInputSignature::new(
                                            sig.sighash_type(),
                                            raw_signature,
                                        )),
                                    )
                                }
                            }
                        }
                    };
                    Ok(script)
                }
                TxOutput::IssueNft(_id, _issuance, dest) => Ok(checksig(dest)),
                TxOutput::DelegateStaking(_amount, _deleg_id) => Err(TranslationError::Unspendable),
                TxOutput::CreateDelegationId(_dest, _pool_id) => Err(TranslationError::Unspendable),
                TxOutput::IssueFungibleToken(_issuance) => Err(TranslationError::Unspendable),
                TxOutput::Burn(_val) => Err(TranslationError::Unspendable),
                TxOutput::DataDeposit(_data) => Err(TranslationError::Unspendable),
                TxOutput::AnyoneCanTake(_) => Err(TranslationError::Unspendable),
            },
            InputInfo::Account { outpoint } => match outpoint.account() {
                AccountSpending::DelegationBalance(delegation_id, _amount) => {
                    let dest = ctx
                        .get_delegation_spend_destination(delegation_id)?
                        .ok_or(TranslationError::DelegationNotFound(*delegation_id))?;
                    Ok(checksig(&dest))
                }
            },
            InputInfo::AccountCommand { command } => match command {
                AccountCommand::MintTokens(token_id, _)
                | AccountCommand::UnmintTokens(token_id)
                | AccountCommand::LockTokenSupply(token_id)
                | AccountCommand::FreezeToken(token_id, _)
                | AccountCommand::UnfreezeToken(token_id)
                | AccountCommand::ChangeTokenAuthority(token_id, _) => {
                    let dest = ctx
                        .get_tokens_authority(token_id)?
                        .ok_or(TranslationError::TokenNotFound(*token_id))?;
                    Ok(checksig(&dest))
                }
                AccountCommand::ConcludeOrder(order_id) => {
                    let dest = ctx
                        .get_orders_conclude_destination(order_id)?
                        .ok_or(TranslationError::OrderNotFound(*order_id))?;
                    Ok(checksig(&dest))
                }
                AccountCommand::FillOrder(_, _, _) => Ok(WitnessScript::TRUE),
            },
        }
    }
}
