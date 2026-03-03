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
        DestinationSigError, EvaluatedInputWitness,
    },
    tokens::TokenId,
    AccountCommand, AccountOutPoint, AccountSpending, DelegationId, Destination,
    OrderAccountCommand, OrderId, PoolId, SignedTransaction, TxOutput, UtxoOutPoint,
};
use utxo::UtxoSource;

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
        utxo: TxOutput,
        utxo_source: Option<UtxoSource>,
    },
    Account {
        outpoint: &'a AccountOutPoint,
    },
    AccountCommand {
        command: &'a AccountCommand,
    },
    OrderAccountCommand {
        command: &'a OrderAccountCommand,
    },
}

pub trait InputInfoProvider {
    fn input_info(&self) -> &InputInfo<'_>;
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

    // Note: this is used for FreezeOrder too.
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
        match ctx.input_info() {
            InputInfo::Utxo {
                outpoint: _,
                utxo,
                utxo_source: _,
            } => match utxo {
                TxOutput::Transfer(_val, dest) => Ok(to_signature_witness_script(ctx, dest)),
                TxOutput::LockThenTransfer(_val, dest, timelock) => {
                    Ok(WitnessScript::satisfied_conjunction([
                        WitnessScript::timelock(*timelock),
                        to_signature_witness_script(ctx, dest),
                    ]))
                }
                TxOutput::CreateStakePool(_pool_id, pool_data) => Ok(to_signature_witness_script(
                    ctx,
                    pool_data.decommission_key(),
                )),
                TxOutput::ProduceBlockFromStake(_, pool_id) => {
                    let dest = ctx
                        .get_pool_decommission_destination(pool_id)?
                        .ok_or(TranslationError::PoolNotFound(*pool_id))?;
                    Ok(to_signature_witness_script(ctx, &dest))
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
                                AuthorizedHashedTimelockContractSpend::Spend(
                                    secret,
                                    raw_signature,
                                ) => WitnessScript::satisfied_conjunction([
                                    WitnessScript::hashlock(
                                        HashChallenge::Hash160(htlc.secret_hash.to_fixed_bytes()),
                                        secret.consume(),
                                    ),
                                    WitnessScript::signature(
                                        htlc.spend_key.clone(),
                                        EvaluatedInputWitness::Standard(
                                            StandardInputSignature::new(
                                                sig.sighash_type(),
                                                raw_signature,
                                            ),
                                        ),
                                    ),
                                ]),
                                AuthorizedHashedTimelockContractSpend::Refund(raw_signature) => {
                                    WitnessScript::satisfied_conjunction([
                                        WitnessScript::timelock(htlc.refund_timelock),
                                        WitnessScript::signature(
                                            htlc.refund_key.clone(),
                                            EvaluatedInputWitness::Standard(
                                                StandardInputSignature::new(
                                                    sig.sighash_type(),
                                                    raw_signature,
                                                ),
                                            ),
                                        ),
                                    ])
                                }
                            }
                        }
                    };
                    Ok(script)
                }
                TxOutput::IssueNft(_id, _issuance, dest) => {
                    Ok(to_signature_witness_script(ctx, dest))
                }
                TxOutput::DelegateStaking(_amount, _deleg_id) => Err(TranslationError::Unspendable),
                TxOutput::CreateDelegationId(_dest, _pool_id) => Err(TranslationError::Unspendable),
                TxOutput::IssueFungibleToken(_issuance) => Err(TranslationError::Unspendable),
                TxOutput::Burn(_val) => Err(TranslationError::Unspendable),
                TxOutput::DataDeposit(_data) => Err(TranslationError::Unspendable),
                TxOutput::CreateOrder(_) => Err(TranslationError::Unspendable),
            },
            InputInfo::Account { outpoint } => match outpoint.account() {
                AccountSpending::DelegationBalance(delegation_id, _amount) => {
                    let dest = ctx
                        .get_delegation_spend_destination(delegation_id)?
                        .ok_or(TranslationError::DelegationNotFound(*delegation_id))?;
                    Ok(to_signature_witness_script(ctx, &dest))
                }
            },
            InputInfo::AccountCommand { command } => match command {
                AccountCommand::MintTokens(token_id, _)
                | AccountCommand::UnmintTokens(token_id)
                | AccountCommand::LockTokenSupply(token_id)
                | AccountCommand::FreezeToken(token_id, _)
                | AccountCommand::UnfreezeToken(token_id)
                | AccountCommand::ChangeTokenMetadataUri(token_id, _)
                | AccountCommand::ChangeTokenAuthority(token_id, _) => {
                    let dest = ctx
                        .get_tokens_authority(token_id)?
                        .ok_or(TranslationError::TokenNotFound(*token_id))?;
                    Ok(to_signature_witness_script(ctx, &dest))
                }
                AccountCommand::ConcludeOrder(order_id) => {
                    let dest = ctx
                        .get_orders_conclude_destination(order_id)?
                        .ok_or(TranslationError::OrderNotFound(*order_id))?;
                    Ok(to_signature_witness_script(ctx, &dest))
                }
                AccountCommand::FillOrder(_, _, _) => {
                    // In orders V0, FillOrder inputs can have arbitrary signatures.
                    Ok(WitnessScript::TRUE)
                }
            },
            InputInfo::OrderAccountCommand { command } => match command {
                OrderAccountCommand::FillOrder(_, _) => {
                    // In orders V1, FillOrder inputs must not be signed.
                    // Note: Destination::AnyoneCanSpend requires InputWitness::NoSignature.
                    Ok(to_signature_witness_script(
                        ctx,
                        &Destination::AnyoneCanSpend,
                    ))
                }
                OrderAccountCommand::FreezeOrder(order_id)
                | OrderAccountCommand::ConcludeOrder(order_id) => {
                    let dest = ctx
                        .get_orders_conclude_destination(order_id)?
                        .ok_or(TranslationError::OrderNotFound(*order_id))?;
                    Ok(to_signature_witness_script(ctx, &dest))
                }
            },
        }
    }
}

impl<C: SignatureInfoProvider> TranslateInput<C> for BlockRewardTransactable<'_> {
    fn translate_input(ctx: &C) -> Result<WitnessScript, TranslationError> {
        match ctx.input_info() {
            InputInfo::Utxo {
                outpoint: _,
                utxo,
                utxo_source: _,
            } => {
                match utxo {
                    TxOutput::Transfer(_, _)
                    | TxOutput::LockThenTransfer(_, _, _)
                    | TxOutput::IssueNft(_, _, _)
                    | TxOutput::Htlc(_, _) => Err(TranslationError::IllegalOutputSpend),
                    TxOutput::CreateDelegationId(_, _)
                    | TxOutput::Burn(_)
                    | TxOutput::DataDeposit(_)
                    | TxOutput::DelegateStaking(_, _)
                    | TxOutput::IssueFungibleToken(_)
                    | TxOutput::CreateOrder(_) => Err(TranslationError::Unspendable),

                    TxOutput::ProduceBlockFromStake(d, _) => {
                        // Spending an output of a block creation output is only allowed to
                        // create another block, given that this is a block reward.
                        Ok(to_signature_witness_script(ctx, d))
                    }
                    TxOutput::CreateStakePool(_, pool_data) => {
                        // Spending an output of a pool creation output is only allowed when
                        // creating a block (given it's in a block reward; otherwise it should
                        // be a transaction for decommissioning the pool), hence the staker key
                        // is checked.
                        Ok(to_signature_witness_script(ctx, pool_data.staker()))
                    }
                }
            }
            InputInfo::Account { .. }
            | InputInfo::AccountCommand { .. }
            | InputInfo::OrderAccountCommand { .. } => Err(TranslationError::IllegalAccountSpend),
        }
    }
}

pub struct TimelockOnly;

impl<C: InputInfoProvider> TranslateInput<C> for TimelockOnly {
    fn translate_input(ctx: &C) -> Result<WitnessScript, TranslationError> {
        match ctx.input_info() {
            InputInfo::Utxo {
                outpoint: _,
                utxo,
                utxo_source: _,
            } => match utxo {
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
                            AuthorizedHashedTimelockContractSpend::Spend(_, _) => {
                                Ok(WitnessScript::TRUE)
                            }
                            AuthorizedHashedTimelockContractSpend::Refund(_) => {
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
                | TxOutput::CreateOrder(_) => Err(TranslationError::Unspendable),
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
                | AccountCommand::ChangeTokenMetadataUri(_token_id, _)
                | AccountCommand::ChangeTokenAuthority(_token_id, _) => Ok(WitnessScript::TRUE),
                AccountCommand::ConcludeOrder(_) | AccountCommand::FillOrder(_, _, _) => {
                    Ok(WitnessScript::TRUE)
                }
            },
            InputInfo::OrderAccountCommand { command } => match command {
                OrderAccountCommand::FillOrder(..)
                | OrderAccountCommand::ConcludeOrder { .. }
                | OrderAccountCommand::FreezeOrder(_) => Ok(WitnessScript::TRUE),
            },
        }
    }
}

pub struct SignatureOnlyTx;

impl<C: SignatureInfoProvider> TranslateInput<C> for SignatureOnlyTx {
    fn translate_input(ctx: &C) -> Result<WitnessScript, TranslationError> {
        match ctx.input_info() {
            InputInfo::Utxo {
                outpoint: _,
                utxo,
                utxo_source: _,
            } => match utxo {
                TxOutput::Transfer(_val, dest) | TxOutput::LockThenTransfer(_val, dest, _) => {
                    Ok(to_signature_witness_script(ctx, dest))
                }
                TxOutput::CreateStakePool(_pool_id, pool_data) => Ok(to_signature_witness_script(
                    ctx,
                    pool_data.decommission_key(),
                )),
                TxOutput::ProduceBlockFromStake(_dest, pool_id) => {
                    let dest = ctx
                        .get_pool_decommission_destination(pool_id)?
                        .ok_or(TranslationError::PoolNotFound(*pool_id))?;
                    Ok(to_signature_witness_script(ctx, &dest))
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
                                AuthorizedHashedTimelockContractSpend::Spend(_, raw_signature) => {
                                    WitnessScript::signature(
                                        htlc.spend_key.clone(),
                                        EvaluatedInputWitness::Standard(
                                            StandardInputSignature::new(
                                                sig.sighash_type(),
                                                raw_signature,
                                            ),
                                        ),
                                    )
                                }
                                AuthorizedHashedTimelockContractSpend::Refund(raw_signature) => {
                                    WitnessScript::signature(
                                        htlc.refund_key.clone(),
                                        EvaluatedInputWitness::Standard(
                                            StandardInputSignature::new(
                                                sig.sighash_type(),
                                                raw_signature,
                                            ),
                                        ),
                                    )
                                }
                            }
                        }
                    };
                    Ok(script)
                }
                TxOutput::IssueNft(_id, _issuance, dest) => {
                    Ok(to_signature_witness_script(ctx, dest))
                }
                TxOutput::DelegateStaking(_amount, _deleg_id) => Err(TranslationError::Unspendable),
                TxOutput::CreateDelegationId(_dest, _pool_id) => Err(TranslationError::Unspendable),
                TxOutput::IssueFungibleToken(_issuance) => Err(TranslationError::Unspendable),
                TxOutput::Burn(_val) => Err(TranslationError::Unspendable),
                TxOutput::DataDeposit(_data) => Err(TranslationError::Unspendable),
                TxOutput::CreateOrder(_) => Err(TranslationError::Unspendable),
            },
            InputInfo::Account { outpoint } => match outpoint.account() {
                AccountSpending::DelegationBalance(delegation_id, _amount) => {
                    let dest = ctx
                        .get_delegation_spend_destination(delegation_id)?
                        .ok_or(TranslationError::DelegationNotFound(*delegation_id))?;
                    Ok(to_signature_witness_script(ctx, &dest))
                }
            },
            InputInfo::AccountCommand { command } => match command {
                AccountCommand::MintTokens(token_id, _)
                | AccountCommand::UnmintTokens(token_id)
                | AccountCommand::LockTokenSupply(token_id)
                | AccountCommand::FreezeToken(token_id, _)
                | AccountCommand::UnfreezeToken(token_id)
                | AccountCommand::ChangeTokenMetadataUri(token_id, _)
                | AccountCommand::ChangeTokenAuthority(token_id, _) => {
                    let dest = ctx
                        .get_tokens_authority(token_id)?
                        .ok_or(TranslationError::TokenNotFound(*token_id))?;
                    Ok(to_signature_witness_script(ctx, &dest))
                }
                AccountCommand::ConcludeOrder(order_id) => {
                    let dest = ctx
                        .get_orders_conclude_destination(order_id)?
                        .ok_or(TranslationError::OrderNotFound(*order_id))?;
                    Ok(to_signature_witness_script(ctx, &dest))
                }
                AccountCommand::FillOrder(_, _, _) => {
                    // In orders V0, FillOrder inputs can have arbitrary signatures.
                    Ok(WitnessScript::TRUE)
                }
            },
            InputInfo::OrderAccountCommand { command } => match command {
                OrderAccountCommand::FillOrder(_, _) => {
                    // In orders V1, FillOrder inputs must not be signed.
                    // Note: Destination::AnyoneCanSpend requires InputWitness::NoSignature.
                    Ok(to_signature_witness_script(
                        ctx,
                        &Destination::AnyoneCanSpend,
                    ))
                }
                OrderAccountCommand::FreezeOrder(order_id)
                | OrderAccountCommand::ConcludeOrder(order_id) => {
                    let dest = ctx
                        .get_orders_conclude_destination(order_id)?
                        .ok_or(TranslationError::OrderNotFound(*order_id))?;
                    Ok(to_signature_witness_script(ctx, &dest))
                }
            },
        }
    }
}

pub struct SignatureOnlyReward;

impl<C: SignatureInfoProvider> TranslateInput<C> for SignatureOnlyReward {
    fn translate_input(_ctx: &C) -> Result<WitnessScript, TranslationError> {
        // Not used anywhere.
        // But it's important to outline that if needed the reward implementation must be different
        // because staking/decommissioning destinations are not the same.
        unimplemented!()
    }
}

fn to_signature_witness_script(
    ctx: &impl SignatureInfoProvider,
    dest: &Destination,
) -> WitnessScript {
    let eval_witness = match ctx.witness().clone() {
        InputWitness::NoSignature(d) => EvaluatedInputWitness::NoSignature(d),
        InputWitness::Standard(s) => EvaluatedInputWitness::Standard(s),
    };
    WitnessScript::signature(dest.clone(), eval_witness)
}
