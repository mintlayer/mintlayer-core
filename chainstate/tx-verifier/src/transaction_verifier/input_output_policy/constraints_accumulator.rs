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

use std::{
    collections::{btree_map::Entry, BTreeMap},
    num::NonZeroU64,
};

use common::{
    chain::{
        output_value::OutputValue,
        timelock::OutputTimeLock,
        tokens::{TokenData, TokenId, TokenIssuanceVersion},
        AccountCommand, AccountSpending, ChainConfig, DelegationId, PoolId, Transaction, TxInput,
        TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id},
};
use utils::ensure;

use crate::{
    transaction_verifier::{CoinOrTokenId, Subsidy},
    Fee,
};

use super::{consumed_constraints_accumulator::ConsumedConstrainedValueAccumulator, IOPolicyError};

/// `ConstrainedValueAccumulator` helps avoiding messy inputs/outputs combinations analysis by
/// providing a set of properties that should be satisfied. For example instead of checking that
/// all outputs are timelocked when the pool is decommissioned `ConstrainedValueAccumulator` gives a way
/// to check that an accumulated output value is locked for sufficient amount of time which allows
/// using other valid inputs and outputs in the same tx.
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

    pub fn new_for_block_reward(total_fee: Fee, subsidy: Subsidy) -> Option<Self> {
        let initial_value = (total_fee.0 + subsidy.0)?;
        Some(Self {
            unconstrained_value: BTreeMap::from_iter([(CoinOrTokenId::Coin, initial_value)]),
            timelock_constrained: Default::default(),
        })
    }

    /// Return accumulated coins that are left
    pub fn consume(self) -> ConsumedConstrainedValueAccumulator {
        ConsumedConstrainedValueAccumulator::from_values(
            self.unconstrained_value,
            self.timelock_constrained,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_inputs<
        PledgeAmountGetterFn,
        DelegationBalanceGetterFn,
        IssuanceTokenIdGetterFn,
    >(
        &mut self,
        chain_config: &ChainConfig,
        block_height: BlockHeight,
        pledge_amount_getter: PledgeAmountGetterFn,
        delegation_balance_getter: DelegationBalanceGetterFn,
        issuance_token_id_getter: IssuanceTokenIdGetterFn,
        inputs: &[TxInput],
        inputs_utxos: &[Option<TxOutput>],
    ) -> Result<(), IOPolicyError>
    where
        PledgeAmountGetterFn: Fn(PoolId) -> Result<Option<Amount>, IOPolicyError>,
        DelegationBalanceGetterFn: Fn(DelegationId) -> Result<Option<Amount>, IOPolicyError>,
        IssuanceTokenIdGetterFn: Fn(Id<Transaction>) -> Result<Option<TokenId>, IOPolicyError>,
    {
        ensure!(
            inputs.len() == inputs_utxos.len(),
            IOPolicyError::InputsAndInputsUtxosLengthMismatch(inputs.len(), inputs_utxos.len())
        );

        let mut total_fee_deducted = Amount::ZERO;

        for (input, input_utxo) in inputs.iter().zip(inputs_utxos.iter()) {
            match input {
                TxInput::Utxo(outpoint) => {
                    let input_utxo = input_utxo
                        .as_ref()
                        .ok_or(IOPolicyError::MissingOutputOrSpent(outpoint.clone()))?;
                    self.process_input_utxo(
                        chain_config,
                        block_height,
                        &pledge_amount_getter,
                        &issuance_token_id_getter,
                        outpoint.clone(),
                        input_utxo,
                    )?;
                }
                TxInput::Account(outpoint) => {
                    self.process_input_account(
                        chain_config,
                        block_height,
                        outpoint.account(),
                        &delegation_balance_getter,
                    )?;
                }
                TxInput::AccountCommand(_, command) => {
                    let fee_to_deduct =
                        self.process_input_account_command(chain_config, command)?;

                    total_fee_deducted = (total_fee_deducted + fee_to_deduct)
                        .ok_or(IOPolicyError::CoinOrTokenOverflow(CoinOrTokenId::Coin))?;
                }
            }
        }

        decrease_or(
            &mut self.unconstrained_value,
            CoinOrTokenId::Coin,
            total_fee_deducted,
            IOPolicyError::AttemptToViolateFeeRequirements,
        )?;

        Ok(())
    }

    fn process_input_utxo<PledgeAmountGetterFn, IssuanceTokenIdGetterFn>(
        &mut self,
        chain_config: &ChainConfig,
        block_height: BlockHeight,
        pledge_amount_getter: &PledgeAmountGetterFn,
        issuance_token_id_getter: &IssuanceTokenIdGetterFn,
        outpoint: UtxoOutPoint,
        input_utxo: &TxOutput,
    ) -> Result<(), IOPolicyError>
    where
        PledgeAmountGetterFn: Fn(PoolId) -> Result<Option<Amount>, IOPolicyError>,
        IssuanceTokenIdGetterFn: Fn(Id<Transaction>) -> Result<Option<TokenId>, IOPolicyError>,
    {
        match input_utxo {
            TxOutput::Transfer(value, _) | TxOutput::LockThenTransfer(value, _, _) => {
                match value {
                    OutputValue::Coin(amount) => insert_or_increase(
                        &mut self.unconstrained_value,
                        CoinOrTokenId::Coin,
                        *amount,
                    )?,
                    OutputValue::TokenV0(token_data) => match token_data.as_ref() {
                        TokenData::TokenTransfer(transfer) => insert_or_increase(
                            &mut self.unconstrained_value,
                            CoinOrTokenId::TokenId(transfer.token_id),
                            transfer.amount,
                        )?,
                        TokenData::TokenIssuance(issuance) => {
                            let issuance_tx_id =
                                outpoint.source_id().get_tx_id().cloned().ok_or(
                                    IOPolicyError::TokenIssuanceInputMustBeTransactionUtxo,
                                )?;
                            let token_id = issuance_token_id_getter(issuance_tx_id)?
                                .ok_or(IOPolicyError::TokenIdNotFound)?;
                            insert_or_increase(
                                &mut self.unconstrained_value,
                                CoinOrTokenId::TokenId(token_id),
                                issuance.amount_to_issue,
                            )?;
                        }
                        TokenData::NftIssuance(_) => {
                            let issuance_tx_id =
                                outpoint.source_id().get_tx_id().cloned().ok_or(
                                    IOPolicyError::TokenIssuanceInputMustBeTransactionUtxo,
                                )?;
                            let token_id = issuance_token_id_getter(issuance_tx_id)?
                                .ok_or(IOPolicyError::TokenIdNotFound)?;
                            insert_or_increase(
                                &mut self.unconstrained_value,
                                CoinOrTokenId::TokenId(token_id),
                                Amount::from_atoms(1),
                            )?;
                        }
                    },
                    OutputValue::TokenV1(token_id, amount) => insert_or_increase(
                        &mut self.unconstrained_value,
                        CoinOrTokenId::TokenId(*token_id),
                        *amount,
                    )?,
                };
            }
            TxOutput::CreateDelegationId(..)
            | TxOutput::IssueFungibleToken(..)
            | TxOutput::Burn(_)
            | TxOutput::DataDeposit(_) => {
                return Err(IOPolicyError::SpendingNonSpendableOutput(outpoint.clone()));
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
                let pledged_amount = pledge_amount_getter(*pool_id)?
                    .ok_or(IOPolicyError::PledgeAmountNotFound(*pool_id))?;
                let maturity_distance =
                    chain_config.staking_pool_spend_maturity_block_count(block_height);

                match NonZeroU64::new(maturity_distance.to_int()) {
                    Some(maturity_distance) => {
                        let balance = self
                            .timelock_constrained
                            .entry(maturity_distance)
                            .or_insert(Amount::ZERO);
                        *balance = (*balance + pledged_amount)
                            .ok_or(IOPolicyError::CoinOrTokenOverflow(CoinOrTokenId::Coin))?;
                    }
                    None => {
                        insert_or_increase(
                            &mut self.unconstrained_value,
                            CoinOrTokenId::Coin,
                            pledged_amount,
                        )?;
                    }
                }
            }
        };

        Ok(())
    }

    fn process_input_account<DelegationBalanceGetterFn>(
        &mut self,
        chain_config: &ChainConfig,
        block_height: BlockHeight,
        account: &AccountSpending,
        delegation_balance_getter: &DelegationBalanceGetterFn,
    ) -> Result<(), IOPolicyError>
    where
        DelegationBalanceGetterFn: Fn(DelegationId) -> Result<Option<Amount>, IOPolicyError>,
    {
        match account {
            AccountSpending::DelegationBalance(delegation_id, spend_amount) => {
                let delegation_balance = delegation_balance_getter(*delegation_id)?
                    .ok_or(IOPolicyError::DelegationBalanceNotFound(*delegation_id))?;
                ensure!(
                    *spend_amount <= delegation_balance,
                    IOPolicyError::AttemptToPrintMoney(CoinOrTokenId::Coin)
                );

                let maturity_distance =
                    chain_config.staking_pool_spend_maturity_block_count(block_height);

                match NonZeroU64::new(maturity_distance.to_int()) {
                    Some(maturity_distance) => {
                        let balance = self
                            .timelock_constrained
                            .entry(maturity_distance)
                            .or_insert(Amount::ZERO);
                        *balance = (*balance + *spend_amount)
                            .ok_or(IOPolicyError::CoinOrTokenOverflow(CoinOrTokenId::Coin))?;
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

    fn process_input_account_command(
        &mut self,
        chain_config: &ChainConfig,
        command: &AccountCommand,
    ) -> Result<Amount, IOPolicyError> {
        match command {
            AccountCommand::MintTokens(token_id, amount) => {
                insert_or_increase(
                    &mut self.unconstrained_value,
                    CoinOrTokenId::TokenId(*token_id),
                    *amount,
                )?;
                Ok(chain_config.token_min_supply_change_fee())
            }
            AccountCommand::LockTokenSupply(_) | AccountCommand::UnmintTokens(_) => {
                Ok(chain_config.token_min_supply_change_fee())
            }
            AccountCommand::FreezeToken(_, _) | AccountCommand::UnfreezeToken(_) => {
                Ok(chain_config.token_min_freeze_fee())
            }
            AccountCommand::ChangeTokenAuthority(_, _) => {
                Ok(chain_config.token_min_change_authority_fee())
            }
        }
    }

    pub fn process_outputs(
        &mut self,
        chain_config: &ChainConfig,
        block_height: BlockHeight,
        outputs: &[TxOutput],
    ) -> Result<(), IOPolicyError> {
        for output in outputs {
            match output {
                TxOutput::Transfer(value, _) | TxOutput::Burn(value) => match value {
                    OutputValue::Coin(amount) => decrease_or(
                        &mut self.unconstrained_value,
                        CoinOrTokenId::Coin,
                        *amount,
                        IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints(
                            CoinOrTokenId::Coin,
                        ),
                    )?,
                    OutputValue::TokenV0(token_data) => match token_data.as_ref() {
                        TokenData::TokenTransfer(transfer) => {
                            decrease_or(
                                &mut self.unconstrained_value,
                                CoinOrTokenId::TokenId(transfer.token_id),
                                transfer.amount,
                                IOPolicyError::AttemptToPrintMoney(CoinOrTokenId::TokenId(
                                    transfer.token_id,
                                )),
                            )?;
                        }
                        TokenData::TokenIssuance(_) | TokenData::NftIssuance(_) => {
                            let latest_token_version = chain_config
                                .chainstate_upgrades()
                                .version_at_height(block_height)
                                .1
                                .token_issuance_version();
                            match latest_token_version {
                                TokenIssuanceVersion::V0 => { /* do nothing */ }
                                TokenIssuanceVersion::V1 => {
                                    decrease_or(
                                        &mut self.unconstrained_value,
                                        CoinOrTokenId::Coin,
                                        chain_config.token_min_issuance_fee(),
                                        IOPolicyError::AttemptToViolateFeeRequirements,
                                    )?;
                                }
                            }
                        }
                    },
                    OutputValue::TokenV1(token_id, amount) => decrease_or(
                        &mut self.unconstrained_value,
                        CoinOrTokenId::TokenId(*token_id),
                        *amount,
                        IOPolicyError::AttemptToPrintMoney(CoinOrTokenId::TokenId(*token_id)),
                    )?,
                },
                TxOutput::DelegateStaking(coins, _) => {
                    decrease_or(
                        &mut self.unconstrained_value,
                        CoinOrTokenId::Coin,
                        *coins,
                        IOPolicyError::AttemptToPrintMoney(CoinOrTokenId::Coin),
                    )?;
                }
                TxOutput::CreateStakePool(_, data) => {
                    decrease_or(
                        &mut self.unconstrained_value,
                        CoinOrTokenId::Coin,
                        data.value(),
                        IOPolicyError::AttemptToPrintMoney(CoinOrTokenId::Coin),
                    )?;
                }
                TxOutput::ProduceBlockFromStake(_, _) | TxOutput::CreateDelegationId(_, _) => {
                    /* do nothing as these outputs cannot produce values */
                }
                TxOutput::LockThenTransfer(value, _, timelock) => match value {
                    OutputValue::Coin(coins) => {
                        self.process_output_timelock(timelock, *coins)?;
                    }
                    OutputValue::TokenV0(token_data) => match token_data.as_ref() {
                        TokenData::TokenTransfer(transfer) => {
                            decrease_or(
                                &mut self.unconstrained_value,
                                CoinOrTokenId::TokenId(transfer.token_id),
                                transfer.amount,
                                IOPolicyError::AttemptToPrintMoney(CoinOrTokenId::TokenId(
                                    transfer.token_id,
                                )),
                            )?;
                        }
                        TokenData::TokenIssuance(_) | TokenData::NftIssuance(_) => {
                            let latest_token_version = chain_config
                                .chainstate_upgrades()
                                .version_at_height(block_height)
                                .1
                                .token_issuance_version();
                            match latest_token_version {
                                TokenIssuanceVersion::V0 => { /* do nothing */ }
                                TokenIssuanceVersion::V1 => {
                                    decrease_or(
                                        &mut self.unconstrained_value,
                                        CoinOrTokenId::Coin,
                                        chain_config.token_min_issuance_fee(),
                                        IOPolicyError::AttemptToViolateFeeRequirements,
                                    )?;
                                }
                            }
                        }
                    },
                    OutputValue::TokenV1(token_id, amount) => decrease_or(
                        &mut self.unconstrained_value,
                        CoinOrTokenId::TokenId(*token_id),
                        *amount,
                        IOPolicyError::AttemptToPrintMoney(CoinOrTokenId::TokenId(*token_id)),
                    )?,
                },
                TxOutput::DataDeposit(_) => {
                    decrease_or(
                        &mut self.unconstrained_value,
                        CoinOrTokenId::Coin,
                        chain_config.data_deposit_min_fee(),
                        IOPolicyError::AttemptToViolateFeeRequirements,
                    )?;
                }
                TxOutput::IssueFungibleToken(_) | TxOutput::IssueNft(_, _, _) => {
                    decrease_or(
                        &mut self.unconstrained_value,
                        CoinOrTokenId::Coin,
                        chain_config.token_min_issuance_fee(),
                        IOPolicyError::AttemptToViolateFeeRequirements,
                    )?;
                }
            };
        }

        Ok(())
    }

    fn process_output_timelock(
        &mut self,
        timelock: &OutputTimeLock,
        locked_coins: Amount,
    ) -> Result<(), IOPolicyError> {
        match timelock {
            OutputTimeLock::UntilHeight(_)
            | OutputTimeLock::UntilTime(_)
            | OutputTimeLock::ForSeconds(_) => {
                decrease_or(
                    &mut self.unconstrained_value,
                    CoinOrTokenId::Coin,
                    locked_coins,
                    IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints(
                        CoinOrTokenId::Coin,
                    ),
                )?;
            }
            OutputTimeLock::ForBlockCount(block_count) => {
                // find the range that can be satisfied with the current timelock
                match NonZeroU64::new(*block_count) {
                    Some(block_count) => {
                        let mut constraint_range_iter = self
                            .timelock_constrained
                            .range_mut((
                                std::ops::Bound::Unbounded,
                                std::ops::Bound::Included(block_count),
                            ))
                            .rev()
                            .peekable();

                        // iterate over the range until current output coins are completely used
                        // or all suitable constraints are satisfied
                        let mut output_coins = locked_coins;
                        while output_coins > Amount::ZERO {
                            match constraint_range_iter.peek_mut() {
                                Some((_, constrained_coins)) => {
                                    if output_coins > **constrained_coins {
                                        // satisfy current constraint completely and move on to the next one
                                        output_coins = (output_coins - **constrained_coins)
                                            .expect("cannot fail");
                                        **constrained_coins = Amount::ZERO;
                                        constraint_range_iter.next();
                                    } else {
                                        // satisfy current constraint partially and exit the loop
                                        **constrained_coins = (**constrained_coins - output_coins)
                                            .expect("cannot fail");
                                        output_coins = Amount::ZERO;
                                    }
                                }
                                None => {
                                    // if the output cannot satisfy any constraints then use it as unconstrained
                                    decrease_or(
                                        &mut self.unconstrained_value,
                                        CoinOrTokenId::Coin,
                                        locked_coins,
                                        IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints(
                                            CoinOrTokenId::Coin,
                                        ),
                                    )?;
                                    output_coins = Amount::ZERO;
                                }
                            };
                        }
                    }
                    None => {
                        decrease_or(
                            &mut self.unconstrained_value,
                            CoinOrTokenId::Coin,
                            locked_coins,
                            IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints(
                                CoinOrTokenId::Coin,
                            ),
                        )?;
                    }
                };
            }
        };

        Ok(())
    }
}

fn insert_or_increase(
    total_amounts: &mut BTreeMap<CoinOrTokenId, Amount>,
    key: CoinOrTokenId,
    amount: Amount,
) -> Result<(), IOPolicyError> {
    match total_amounts.entry(key) {
        Entry::Occupied(mut entry) => {
            let value = entry.get_mut();
            *value = (*value + amount).ok_or(IOPolicyError::CoinOrTokenOverflow(key))?;
        }
        Entry::Vacant(ventry) => {
            ventry.insert(amount);
        }
    }
    Ok(())
}

fn decrease_or(
    total_amounts: &mut BTreeMap<CoinOrTokenId, Amount>,
    key: CoinOrTokenId,
    amount: Amount,
    error: IOPolicyError,
) -> Result<(), IOPolicyError> {
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
