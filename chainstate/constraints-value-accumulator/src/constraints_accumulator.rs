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

use std::{collections::BTreeMap, num::NonZeroU64};

use common::{
    chain::{
        output_value::OutputValue, timelock::OutputTimeLock, AccountCommand, AccountSpending,
        AccountType, ChainConfig, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, CoinOrTokenId, Fee, Subsidy},
};
use orders_accounting::{OrdersAccountingOperations, OrdersAccountingView};
use pos_accounting::{PoSAccountingOperations, PoSAccountingUndo, PoSAccountingView};
use tokens_accounting::{TokensAccountingOperations, TokensAccountingView};
use utils::ensure;

use super::{accumulated_fee::AccumulatedFee, insert_or_increase, Error};

/// `ConstrainedValueAccumulator` helps avoiding messy inputs/outputs combinations analysis by
/// providing a set of properties that should be satisfied. For example instead of checking that
/// all outputs are timelocked when the pool is decommissioned `ConstrainedValueAccumulator` gives a way
/// to check that an accumulated output value is locked for sufficient amount of time which allows
/// using other valid inputs and outputs in the same tx.
#[derive(Debug, PartialEq, Eq)]
pub struct ConstrainedValueAccumulator {
    unconstrained_value: BTreeMap<CoinOrTokenId, Amount>,
    timelock_constrained: BTreeMap<NonZeroU64, Amount>,
}

impl ConstrainedValueAccumulator {
    pub fn new() -> Self {
        Self {
            unconstrained_value: Default::default(),
            timelock_constrained: Default::default(),
        }
    }

    pub fn from_block_reward(total_fee: Fee, subsidy: Subsidy) -> Option<Self> {
        let initial_value = (total_fee.0 + subsidy.0)?;
        Some(Self {
            unconstrained_value: BTreeMap::from_iter([(CoinOrTokenId::Coin, initial_value)]),
            timelock_constrained: Default::default(),
        })
    }

    pub fn from_inputs(
        chain_config: &ChainConfig,
        block_height: BlockHeight,
        orders_accounting_view: &impl OrdersAccountingView,
        pos_accounting_view: &impl PoSAccountingView,
        tokens_accounting_view: &impl TokensAccountingView,
        inputs: &[TxInput],
        inputs_utxos: &[Option<TxOutput>],
    ) -> Result<Self, Error> {
        ensure!(
            inputs.len() == inputs_utxos.len(),
            Error::InputsAndInputsUtxosLengthMismatch(inputs.len(), inputs_utxos.len())
        );

        let mut accumulator = Self::new();
        let mut total_to_deduct = BTreeMap::<CoinOrTokenId, Amount>::new();

        // Temp deltas are used to check accounting errors like overspends across multiple inputs
        let mut temp_pos_accounting = pos_accounting::PoSAccountingDelta::new(pos_accounting_view);
        let mut temp_tokens_accounting =
            tokens_accounting::TokensAccountingCache::new(tokens_accounting_view);
        let mut temp_orders_accounting =
            orders_accounting::OrdersAccountingCache::new(orders_accounting_view);

        for (input, input_utxo) in inputs.iter().zip(inputs_utxos.iter()) {
            match input {
                TxInput::Utxo(outpoint) => {
                    let input_utxo =
                        input_utxo.as_ref().ok_or(Error::MissingOutputOrSpent(outpoint.clone()))?;
                    accumulator.process_input_utxo(
                        chain_config,
                        block_height,
                        &temp_pos_accounting,
                        outpoint.clone(),
                        input_utxo,
                    )?;
                }
                TxInput::Account(outpoint) => {
                    accumulator.process_input_account(
                        chain_config,
                        block_height,
                        outpoint.account(),
                        &mut temp_pos_accounting,
                    )?;
                }
                TxInput::AccountCommand(_, command) => {
                    let (id, to_deduct) = accumulator.process_input_account_command(
                        chain_config,
                        block_height,
                        command,
                        &mut temp_orders_accounting,
                        &mut temp_tokens_accounting,
                    )?;

                    insert_or_increase(&mut total_to_deduct, id, to_deduct)?;
                }
                TxInput::OrderAccountCommand(_) => todo!(),
            }
        }

        for (currency, amount) in total_to_deduct {
            decrease_or(
                &mut accumulator.unconstrained_value,
                currency,
                amount,
                Error::AttemptToViolateFeeRequirements,
            )?;
        }

        Ok(accumulator)
    }

    fn process_input_utxo(
        &mut self,
        chain_config: &ChainConfig,
        block_height: BlockHeight,
        pos_accounting_view: &impl PoSAccountingView,
        outpoint: UtxoOutPoint,
        input_utxo: &TxOutput,
    ) -> Result<(), Error> {
        match input_utxo {
            TxOutput::Transfer(value, _)
            | TxOutput::LockThenTransfer(value, _, _)
            | TxOutput::Htlc(value, _) => {
                match value {
                    OutputValue::Coin(amount) => insert_or_increase(
                        &mut self.unconstrained_value,
                        CoinOrTokenId::Coin,
                        *amount,
                    )?,
                    OutputValue::TokenV0(_) => { /* ignore */ }
                    OutputValue::TokenV1(token_id, amount) => insert_or_increase(
                        &mut self.unconstrained_value,
                        CoinOrTokenId::TokenId(*token_id),
                        *amount,
                    )?,
                };
            }
            TxOutput::CreateDelegationId(..)
            | TxOutput::IssueFungibleToken(..)
            | TxOutput::Burn(..)
            | TxOutput::DataDeposit(..)
            | TxOutput::CreateOrder(..) => {
                return Err(Error::SpendingNonSpendableOutput(outpoint.clone()));
            }
            TxOutput::IssueNft(token_id, _, _) => {
                insert_or_increase(
                    &mut self.unconstrained_value,
                    CoinOrTokenId::TokenId(*token_id),
                    Amount::from_atoms(1),
                )?;
            }
            TxOutput::DelegateStaking(coins, _) => {
                insert_or_increase(&mut self.unconstrained_value, CoinOrTokenId::Coin, *coins)?;
            }
            TxOutput::CreateStakePool(pool_id, _) | TxOutput::ProduceBlockFromStake(_, pool_id) => {
                let staker_balance = pos_accounting_view
                    .get_pool_data(*pool_id)
                    .map_err(|_| pos_accounting::Error::ViewFail)?
                    .map(|pool_data| pool_data.staker_balance())
                    .transpose()
                    .map_err(Error::PoSAccountingError)?
                    .ok_or(Error::PledgeAmountNotFound(*pool_id))?;

                let maturity_distance =
                    chain_config.staking_pool_spend_maturity_block_count(block_height);

                match NonZeroU64::new(maturity_distance.to_int()) {
                    Some(maturity_distance) => {
                        let balance = self
                            .timelock_constrained
                            .entry(maturity_distance)
                            .or_insert(Amount::ZERO);
                        *balance = (*balance + staker_balance)
                            .ok_or(Error::CoinOrTokenOverflow(CoinOrTokenId::Coin))?;
                    }
                    None => {
                        insert_or_increase(
                            &mut self.unconstrained_value,
                            CoinOrTokenId::Coin,
                            staker_balance,
                        )?;
                    }
                }
            }
        };

        Ok(())
    }

    fn process_input_account<P>(
        &mut self,
        chain_config: &ChainConfig,
        block_height: BlockHeight,
        account: &AccountSpending,
        pos_accounting_delta: &mut P,
    ) -> Result<(), Error>
    where
        P: PoSAccountingOperations<PoSAccountingUndo>
            + PoSAccountingView<Error = pos_accounting::Error>,
    {
        match account {
            AccountSpending::DelegationBalance(delegation_id, spend_amount) => {
                {
                    // Ensure that spending won't result in negative balance
                    let _ = pos_accounting_delta
                        .spend_share_from_delegation_id(*delegation_id, *spend_amount)?;
                    let _ = pos_accounting_delta.get_delegation_balance(*delegation_id)?;
                }

                let maturity_distance =
                    chain_config.staking_pool_spend_maturity_block_count(block_height);

                match NonZeroU64::new(maturity_distance.to_int()) {
                    Some(maturity_distance) => {
                        let balance = self
                            .timelock_constrained
                            .entry(maturity_distance)
                            .or_insert(Amount::ZERO);
                        *balance = (*balance + *spend_amount)
                            .ok_or(Error::CoinOrTokenOverflow(CoinOrTokenId::Coin))?;
                    }
                    None => {
                        insert_or_increase(
                            &mut self.unconstrained_value,
                            CoinOrTokenId::Coin,
                            *spend_amount,
                        )?;
                    }
                }
            }
        };

        Ok(())
    }

    fn process_input_account_command<O, T>(
        &mut self,
        chain_config: &ChainConfig,
        block_height: BlockHeight,
        command: &AccountCommand,
        orders_accounting_delta: &mut O,
        tokens_accounting_delta: &mut T,
    ) -> Result<(CoinOrTokenId, Amount), Error>
    where
        O: OrdersAccountingOperations + OrdersAccountingView<Error = orders_accounting::Error>,
        T: TokensAccountingOperations + TokensAccountingView<Error = tokens_accounting::Error>,
    {
        match command {
            AccountCommand::MintTokens(id, amount) => {
                let _ = tokens_accounting_delta.mint_tokens(*id, *amount)?;
                let _ = tokens_accounting_delta.get_circulating_supply(id)?;

                insert_or_increase(
                    &mut self.unconstrained_value,
                    CoinOrTokenId::TokenId(*id),
                    *amount,
                )?;
                Ok((
                    CoinOrTokenId::Coin,
                    chain_config.token_supply_change_fee(block_height),
                ))
            }
            AccountCommand::LockTokenSupply(_) | AccountCommand::UnmintTokens(_) => Ok((
                CoinOrTokenId::Coin,
                chain_config.token_supply_change_fee(block_height),
            )),
            AccountCommand::FreezeToken(_, _) | AccountCommand::UnfreezeToken(_) => Ok((
                CoinOrTokenId::Coin,
                chain_config.token_freeze_fee(block_height),
            )),
            AccountCommand::ChangeTokenAuthority(_, _) => Ok((
                CoinOrTokenId::Coin,
                chain_config.token_change_authority_fee(block_height),
            )),
            AccountCommand::ChangeTokenMetadataUri(_, _) => Ok((
                CoinOrTokenId::Coin,
                chain_config.token_change_metadata_uri_fee(),
            )),
            AccountCommand::ConcludeOrder(id) => {
                let order_data = orders_accounting_delta
                    .get_order_data(id)
                    .map_err(|_| orders_accounting::Error::ViewFail)?
                    .ok_or(orders_accounting::Error::OrderDataNotFound(*id))?;
                let ask_balance = orders_accounting_delta
                    .get_ask_balance(id)
                    .map_err(|_| orders_accounting::Error::ViewFail)?;
                let give_balance = orders_accounting_delta
                    .get_give_balance(id)
                    .map_err(|_| orders_accounting::Error::ViewFail)?;

                {
                    // Ensure that spending won't result in negative balance
                    let _ = orders_accounting_delta.conclude_order(*id)?;
                    let _ = orders_accounting_delta.get_ask_balance(id)?;
                    let _ = orders_accounting_delta.get_give_balance(id)?;
                }

                let initially_asked = output_value_amount(order_data.ask())?;
                let filled_amount = (initially_asked - ask_balance)
                    .ok_or(Error::NegativeAccountBalance(AccountType::Order(*id)))?;

                let ask_currency = CoinOrTokenId::from_output_value(order_data.ask())
                    .ok_or(Error::UnsupportedTokenVersion)?;
                insert_or_increase(&mut self.unconstrained_value, ask_currency, filled_amount)?;

                let give_currency = CoinOrTokenId::from_output_value(order_data.give())
                    .ok_or(Error::UnsupportedTokenVersion)?;
                insert_or_increase(&mut self.unconstrained_value, give_currency, give_balance)?;

                Ok((CoinOrTokenId::Coin, Amount::ZERO))
            }
            AccountCommand::FillOrder(id, fill_amount_in_ask_currency, _) => {
                let order_data = orders_accounting_delta
                    .get_order_data(id)
                    .map_err(|_| orders_accounting::Error::ViewFail)?
                    .ok_or(orders_accounting::Error::OrderDataNotFound(*id))?;
                let orders_version = chain_config
                    .chainstate_upgrades()
                    .version_at_height(block_height)
                    .1
                    .orders_version();
                let filled_amount = orders_accounting::calculate_fill_order(
                    &orders_accounting_delta,
                    *id,
                    *fill_amount_in_ask_currency,
                    orders_version,
                )?;

                {
                    // Ensure that spending won't result in negative balance
                    let _ = orders_accounting_delta.fill_order(
                        *id,
                        *fill_amount_in_ask_currency,
                        orders_version,
                    )?;
                    let _ = orders_accounting_delta.get_ask_balance(id)?;
                    let _ = orders_accounting_delta.get_give_balance(id)?;
                }

                let give_currency = CoinOrTokenId::from_output_value(order_data.give())
                    .ok_or(Error::UnsupportedTokenVersion)?;
                insert_or_increase(&mut self.unconstrained_value, give_currency, filled_amount)?;

                let ask_currency = CoinOrTokenId::from_output_value(order_data.ask())
                    .ok_or(Error::UnsupportedTokenVersion)?;

                Ok((ask_currency, *fill_amount_in_ask_currency))
            }
        }
    }

    pub fn from_outputs(
        chain_config: &ChainConfig,
        block_height: BlockHeight,
        outputs: &[TxOutput],
    ) -> Result<Self, Error> {
        let mut accumulator = Self::new();

        for output in outputs {
            match output {
                TxOutput::Transfer(value, _) | TxOutput::Burn(value) | TxOutput::Htlc(value, _) => {
                    match value {
                        OutputValue::Coin(amount) => insert_or_increase(
                            &mut accumulator.unconstrained_value,
                            CoinOrTokenId::Coin,
                            *amount,
                        )?,
                        OutputValue::TokenV0(_) => { /* ignore */ }
                        OutputValue::TokenV1(token_id, amount) => insert_or_increase(
                            &mut accumulator.unconstrained_value,
                            CoinOrTokenId::TokenId(*token_id),
                            *amount,
                        )?,
                    }
                }
                TxOutput::DelegateStaking(coins, _) => insert_or_increase(
                    &mut accumulator.unconstrained_value,
                    CoinOrTokenId::Coin,
                    *coins,
                )?,
                TxOutput::CreateStakePool(_, data) => insert_or_increase(
                    &mut accumulator.unconstrained_value,
                    CoinOrTokenId::Coin,
                    data.pledge(),
                )?,
                TxOutput::ProduceBlockFromStake(_, _) | TxOutput::CreateDelegationId(_, _) => {
                    /* do nothing as these outputs cannot produce values */
                }
                TxOutput::LockThenTransfer(value, _, timelock) => match value {
                    OutputValue::Coin(coins) => {
                        accumulator.process_output_timelock(timelock, *coins)?;
                    }
                    OutputValue::TokenV0(_) => { /* ignore */ }
                    OutputValue::TokenV1(token_id, amount) => insert_or_increase(
                        &mut accumulator.unconstrained_value,
                        CoinOrTokenId::TokenId(*token_id),
                        *amount,
                    )?,
                },
                TxOutput::DataDeposit(_) => insert_or_increase(
                    &mut accumulator.unconstrained_value,
                    CoinOrTokenId::Coin,
                    chain_config.data_deposit_fee(block_height),
                )?,
                TxOutput::IssueFungibleToken(_) => insert_or_increase(
                    &mut accumulator.unconstrained_value,
                    CoinOrTokenId::Coin,
                    chain_config.fungible_token_issuance_fee(),
                )?,
                TxOutput::IssueNft(_, _, _) => insert_or_increase(
                    &mut accumulator.unconstrained_value,
                    CoinOrTokenId::Coin,
                    chain_config.nft_issuance_fee(block_height),
                )?,
                TxOutput::CreateOrder(order_data) => {
                    let id = CoinOrTokenId::from_output_value(order_data.give())
                        .ok_or(Error::UnsupportedTokenVersion)?;
                    insert_or_increase(
                        &mut accumulator.unconstrained_value,
                        id,
                        output_value_amount(order_data.give())?,
                    )?;
                }
            };
        }

        Ok(accumulator)
    }

    fn process_output_timelock(
        &mut self,
        timelock: &OutputTimeLock,
        locked_coins: Amount,
    ) -> Result<(), Error> {
        match timelock {
            OutputTimeLock::UntilHeight(_)
            | OutputTimeLock::UntilTime(_)
            | OutputTimeLock::ForSeconds(_) => insert_or_increase(
                &mut self.unconstrained_value,
                CoinOrTokenId::Coin,
                locked_coins,
            )?,
            OutputTimeLock::ForBlockCount(block_count) => {
                match NonZeroU64::new(*block_count) {
                    Some(block_count) => insert_or_increase(
                        &mut self.timelock_constrained,
                        block_count,
                        locked_coins,
                    )?,
                    None => insert_or_increase(
                        &mut self.unconstrained_value,
                        CoinOrTokenId::Coin,
                        locked_coins,
                    )?,
                };
            }
        };

        Ok(())
    }

    // Satisfy current constraints with other accumulator.
    pub fn satisfy_with(mut self, other: Self) -> Result<AccumulatedFee, Error> {
        for (key, value) in other.unconstrained_value {
            decrease_or(
                &mut self.unconstrained_value,
                key,
                value,
                Error::AttemptToPrintMoneyOrViolateTimelockConstraints(key),
            )?;
        }

        for (timelock, locked_coins) in other.timelock_constrained {
            // if the output cannot satisfy any constraints then use it falls back to unconstrained
            let mut constraint_range_iter = self
                .unconstrained_value
                .get_mut(&CoinOrTokenId::Coin)
                .into_iter()
                .chain(
                    self.timelock_constrained
                        .range_mut((
                            std::ops::Bound::Unbounded,
                            std::ops::Bound::Included(timelock),
                        ))
                        .map(|(_, v)| v),
                )
                .rev()
                .peekable();

            // iterate over the range until current output coins are completely used
            // or all suitable constraints are satisfied
            let mut output_coins = locked_coins;
            while output_coins > Amount::ZERO {
                let constrained_coins = constraint_range_iter.peek_mut().ok_or(
                    Error::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin),
                )?;

                if output_coins > **constrained_coins {
                    // satisfy current constraint completely and move on to the next one
                    output_coins = (output_coins - **constrained_coins).expect("cannot fail");
                    **constrained_coins = Amount::ZERO;
                    constraint_range_iter.next();
                } else {
                    // satisfy current constraint partially and exit the loop
                    **constrained_coins =
                        (**constrained_coins - output_coins).expect("cannot fail");
                    output_coins = Amount::ZERO;
                }
            }
        }

        Ok(AccumulatedFee::from_data(
            self.unconstrained_value,
            self.timelock_constrained,
        ))
    }
}

fn decrease_or(
    total_amounts: &mut BTreeMap<CoinOrTokenId, Amount>,
    key: CoinOrTokenId,
    amount: Amount,
    error: Error,
) -> Result<(), Error> {
    if amount > Amount::ZERO {
        match total_amounts.get_mut(&key) {
            Some(value) => {
                *value = (*value - amount).ok_or(error)?;
            }
            None => {
                return Err(error);
            }
        }
    }
    Ok(())
}

fn output_value_amount(value: &OutputValue) -> Result<Amount, Error> {
    match value {
        OutputValue::Coin(amount) | OutputValue::TokenV1(_, amount) => Ok(*amount),
        OutputValue::TokenV0(_) => Err(Error::UnsupportedTokenVersion),
    }
}
