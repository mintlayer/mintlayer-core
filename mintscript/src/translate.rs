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
    block::BlockRewardTransactable, signature::inputsig::InputWitness, tokens::TokenId,
    AccountCommand, AccountOutPoint, AccountSpending, DelegationId, Destination, PoolId,
    SignedTransaction, TxOutput, UtxoOutPoint,
};
use pos_accounting::PoSAccountingView;
use tokens_accounting::TokensAccountingView;
use utxo::Utxo;

use crate::WitnessScript;

/// An error that can happen during translation of an input to a script
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
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

    #[error("Stake pool {0} does not exist")]
    PoolNotFound(PoolId),

    #[error("Delegation {0} does not exist")]
    DelegationNotFound(DelegationId),

    #[error("Token with id {0} does not exist")]
    TokenNotFound(TokenId),
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
    type Accounting: PoSAccountingView<Error = pos_accounting::Error>;
    type Tokens: TokensAccountingView<Error = tokens_accounting::Error>;

    fn pos_accounting(&self) -> &Self::Accounting;
    fn tokens(&self) -> &Self::Tokens;
}

pub trait TranslateInput<C> {
    /// Translate transaction input to script.
    fn translate_input(ctx: &C) -> Result<WitnessScript, TranslationError>;
}

impl<C: SignatureInfoProvider> TranslateInput<C> for SignedTransaction {
    fn translate_input(ctx: &C) -> Result<WitnessScript, TranslationError> {
        let pos_accounting = ctx.pos_accounting();
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
                TxOutput::ProduceBlockFromStake(_dest, pool_id) => {
                    let pool_data = pos_accounting
                        .get_pool_data(*pool_id)?
                        .ok_or(TranslationError::PoolNotFound(*pool_id))?;
                    Ok(checksig(pool_data.decommission_destination()))
                }
                TxOutput::DelegateStaking(_amount, delegation_id) => {
                    let delegation = pos_accounting
                        .get_delegation_data(*delegation_id)?
                        .ok_or(TranslationError::DelegationNotFound(*delegation_id))?;
                    Ok(checksig(delegation.spend_destination()))
                }
                TxOutput::IssueNft(_id, _issuance, dest) => Ok(checksig(dest)),
                TxOutput::CreateDelegationId(_dest, _pool_id) => Err(TranslationError::Unspendable),
                TxOutput::IssueFungibleToken(_issuance) => Err(TranslationError::Unspendable),
                TxOutput::Burn(_val) => Err(TranslationError::Unspendable),
                TxOutput::DataDeposit(_data) => Err(TranslationError::Unspendable),
            },
            InputInfo::Account { outpoint } => match outpoint.account() {
                AccountSpending::DelegationBalance(delegation_id, _amount) => {
                    let delegation = pos_accounting
                        .get_delegation_data(*delegation_id)?
                        .ok_or(TranslationError::DelegationNotFound(*delegation_id))?;
                    Ok(checksig(delegation.spend_destination()))
                }
            },
            InputInfo::AccountCommand { command } => match command {
                AccountCommand::MintTokens(token_id, _)
                | AccountCommand::UnmintTokens(token_id)
                | AccountCommand::LockTokenSupply(token_id)
                | AccountCommand::FreezeToken(token_id, _)
                | AccountCommand::UnfreezeToken(token_id)
                | AccountCommand::ChangeTokenAuthority(token_id, _) => {
                    let token_data = ctx
                        .tokens()
                        .get_token_data(token_id)?
                        .ok_or(TranslationError::TokenNotFound(*token_id))?;
                    let dest = match &token_data {
                        tokens_accounting::TokenData::FungibleToken(data) => data.authority(),
                    };
                    Ok(checksig(dest))
                }
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
                    | TxOutput::DelegateStaking(_, _)
                    | TxOutput::IssueNft(_, _, _) => {
                        Err(TranslationError::IllegalOutputSpend)
                    }
                    TxOutput::CreateDelegationId(_, _)
                    | TxOutput::Burn(_)
                    | TxOutput::DataDeposit(_)
                    | TxOutput::IssueFungibleToken(_) => {
                        Err(TranslationError::Unspendable)
                    }

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
            InputInfo::Account {..} | InputInfo::AccountCommand {..} => {
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
                TxOutput::Transfer(_, _)
                | TxOutput::CreateStakePool(_, _)
                | TxOutput::ProduceBlockFromStake(_, _)
                | TxOutput::DelegateStaking(_, _)
                | TxOutput::IssueNft(_, _, _) => Ok(WitnessScript::TRUE),
                TxOutput::CreateDelegationId(_, _)
                | TxOutput::IssueFungibleToken(_)
                | TxOutput::Burn(_)
                | TxOutput::DataDeposit(_) => Err(TranslationError::Unspendable),
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
            },
        }
    }
}
