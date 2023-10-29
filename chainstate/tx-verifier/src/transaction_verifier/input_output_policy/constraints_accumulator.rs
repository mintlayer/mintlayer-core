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

use std::collections::{btree_map::Entry, BTreeMap};

use common::{
    chain::{
        output_value::OutputValue,
        timelock::OutputTimeLock,
        tokens::{TokenData, TokenId},
        AccountCommand, AccountSpending, ChainConfig, DelegationId, PoolId, TxInput, TxOutput,
    },
    primitives::{Amount, BlockDistance, BlockHeight},
};
use utils::ensure;

use crate::{transaction_verifier::amounts_map::CoinOrTokenId, Fee};

use super::IOPolicyError;

/// `ConstrainedValueAccumulator` helps avoiding messy inputs/outputs combinations analysis by
/// providing a set of properties that should be satisfied. For example instead of checking that
/// all outputs are timelocked when the pool is decommissioned `ConstrainedValueAccumulator` gives a way
/// to check that an accumulated output value is locked for sufficient amount of time which allows
/// using other valid inputs and outputs in the same tx.
///
/// TODO: this struct can be extended to collect tokens replacing `AmountsMap`
pub struct ConstrainedValueAccumulator {
    unconstrained_value: BTreeMap<CoinOrTokenId, Amount>,
    // FIXME: zero timelocks go to unconstrained
    // FIXME: tests from homomorphism
    timelock_constrained: BTreeMap<BlockDistance, Amount>, // FIXME: how to enforce coins?
}

impl ConstrainedValueAccumulator {
    pub fn new() -> Self {
        Self {
            unconstrained_value: Default::default(),
            timelock_constrained: Default::default(),
        }
    }

    /// Return accumulated amounts that are left
    // FIXME: tests for fee
    pub fn consume(self) -> Result<Fee, IOPolicyError> {
        let unconstrained_change = self
            .unconstrained_value
            .get(&CoinOrTokenId::Coin)
            .cloned()
            .unwrap_or(Amount::ZERO);

        // FIXME: if output is more then decomission period then it can't go to the fee
        let timelocked_change = self
            .timelock_constrained
            .into_values()
            .sum::<Option<Amount>>()
            .ok_or(IOPolicyError::CoinOrTokenOverflow(CoinOrTokenId::Coin))?;

        let fee = (unconstrained_change + timelocked_change)
            .ok_or(IOPolicyError::CoinOrTokenOverflow(CoinOrTokenId::Coin))?;

        Ok(Fee(fee))
    }

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
        IssuanceTokenIdGetterFn: Fn() -> Result<Option<TokenId>, IOPolicyError>,
    {
        ensure!(
            inputs.len() == inputs_utxos.len(),
            IOPolicyError::InputsAndInputsUtxosLengthMismatch(inputs.len(), inputs_utxos.len())
        );

        let mut total_fee_deducted = Amount::ZERO;

        for (input, input_utxo) in inputs.iter().zip(inputs_utxos.iter()) {
            match input {
                TxInput::Utxo(outpoint) => {
                    match input_utxo
                        .as_ref()
                        .ok_or(IOPolicyError::MissingOutputOrSpent(outpoint.clone()))?
                    {
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
                                        let token_id = issuance_token_id_getter()?
                                            .ok_or(IOPolicyError::TokenIdNotFound)?;
                                        insert_or_increase(
                                            &mut self.unconstrained_value,
                                            CoinOrTokenId::TokenId(token_id),
                                            issuance.amount_to_issue,
                                        )?;
                                    }
                                    TokenData::NftIssuance(_) => {
                                        let token_id = issuance_token_id_getter()?
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
                            return Err(IOPolicyError::SpendingNonSpendableOutput(
                                outpoint.clone(),
                            ));
                        }
                        TxOutput::IssueNft(token_id, _, _) => {
                            // FIXME: is there a test for printing?
                            insert_or_increase(
                                &mut self.unconstrained_value,
                                CoinOrTokenId::TokenId(*token_id),
                                Amount::from_atoms(1),
                            )?;
                        }
                        TxOutput::DelegateStaking(coins, _) => {
                            insert_or_increase(
                                &mut self.unconstrained_value,
                                CoinOrTokenId::Coin,
                                *coins,
                            )?;
                        }
                        TxOutput::CreateStakePool(pool_id, _)
                        | TxOutput::ProduceBlockFromStake(_, pool_id) => {
                            let block_distance = chain_config
                                .as_ref()
                                .staking_pool_spend_maturity_distance(block_height);
                            let pledged_amount = pledge_amount_getter(*pool_id)?
                                .ok_or(IOPolicyError::PledgeAmountNotFound(*pool_id))?;

                            let balance = self
                                .timelock_constrained
                                .entry(block_distance)
                                .or_insert(Amount::ZERO);
                            *balance = (*balance + pledged_amount)
                                .ok_or(IOPolicyError::CoinOrTokenOverflow(CoinOrTokenId::Coin))?;
                        }
                    };
                }
                TxInput::Account(outpoint) => {
                    match outpoint.account() {
                        AccountSpending::DelegationBalance(delegation_id, spend_amount) => {
                            let delegation_balance = delegation_balance_getter(*delegation_id)?
                                .ok_or(IOPolicyError::DelegationBalanceNotFound(*delegation_id))?;
                            ensure!(
                                *spend_amount <= delegation_balance,
                                IOPolicyError::AttemptToPrintMoney(CoinOrTokenId::Coin)
                            );

                            let block_distance = chain_config
                                .as_ref()
                                .staking_pool_spend_maturity_distance(block_height);

                            let balance = self
                                .timelock_constrained
                                .entry(block_distance)
                                .or_insert(Amount::ZERO);
                            *balance = (*balance + *spend_amount)
                                .ok_or(IOPolicyError::CoinOrTokenOverflow(CoinOrTokenId::Coin))?;
                        }
                    };
                }
                TxInput::AccountCommand(_, command) => {
                    match command {
                        AccountCommand::MintTokens(token_id, amount) => {
                            total_fee_deducted = (total_fee_deducted
                                + chain_config.token_min_supply_change_fee())
                            .ok_or(IOPolicyError::CoinOrTokenOverflow(CoinOrTokenId::Coin))?;

                            insert_or_increase(
                                &mut self.unconstrained_value,
                                CoinOrTokenId::TokenId(*token_id),
                                *amount,
                            )?;
                        }
                        AccountCommand::LockTokenSupply(_) | AccountCommand::UnmintTokens(_) => {
                            total_fee_deducted = (total_fee_deducted
                                + chain_config.token_min_supply_change_fee())
                            .ok_or(IOPolicyError::CoinOrTokenOverflow(CoinOrTokenId::Coin))?;
                        }
                        AccountCommand::FreezeToken(_, _) | AccountCommand::UnfreezeToken(_) => {
                            total_fee_deducted = (total_fee_deducted
                                + chain_config.token_min_freeze_fee())
                            .ok_or(IOPolicyError::CoinOrTokenOverflow(CoinOrTokenId::Coin))?;
                        }
                        AccountCommand::ChangeTokenAuthority(_, _) => {
                            total_fee_deducted = (total_fee_deducted
                                + chain_config.token_min_change_authority_fee())
                            .ok_or(IOPolicyError::CoinOrTokenOverflow(CoinOrTokenId::Coin))?;
                        }
                    };
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

    pub fn process_outputs(
        &mut self,
        chain_config: &ChainConfig,
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
                            decrease_or(
                                &mut self.unconstrained_value,
                                CoinOrTokenId::Coin,
                                chain_config.token_min_issuance_fee(),
                                IOPolicyError::AttemptToViolateFeeRequirements,
                            )?;
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
                TxOutput::LockThenTransfer(value, _, timelock) => {
                    match value {
                        OutputValue::Coin(coins) => {
                            match timelock {
                                OutputTimeLock::UntilHeight(_)
                                | OutputTimeLock::UntilTime(_)
                                | OutputTimeLock::ForSeconds(_) => {
                                    decrease_or(
                                        &mut self.unconstrained_value,
                                        CoinOrTokenId::Coin,
                                        *coins,
                                        IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin)
                                    )?;
                                }
                                OutputTimeLock::ForBlockCount(block_count) => {
                                    let block_count: i64 = (*block_count)
                                        .try_into()
                                        .map_err(|_| IOPolicyError::BlockHeightArithmeticError)?;
                                    let distance = BlockDistance::from(block_count);

                                    // find the range that can be satisfied with the current timelock
                                    let mut constraint_range_iter = self
                                        .timelock_constrained
                                        .range_mut((
                                            std::ops::Bound::Unbounded,
                                            std::ops::Bound::Included(distance),
                                        ))
                                        .rev()
                                        .peekable();

                                    // iterate over the range until current output coins are completely used
                                    // or all suitable constraints are satisfied
                                    let mut output_coins = *coins;
                                    while output_coins > Amount::ZERO {
                                        match constraint_range_iter.peek_mut() {
                                            Some((_, constrained_coins)) => {
                                                if output_coins > **constrained_coins {
                                                    // satisfy current constraint completely and move on to the next one
                                                    output_coins = (output_coins
                                                        - **constrained_coins)
                                                        .expect("cannot fail");
                                                    **constrained_coins = Amount::ZERO;
                                                    constraint_range_iter.next();
                                                } else {
                                                    // satisfy current constraint partially and exit the loop
                                                    **constrained_coins = (**constrained_coins
                                                        - output_coins)
                                                        .expect("cannot fail");
                                                    output_coins = Amount::ZERO;
                                                }
                                            }
                                            None => {
                                                // if the output cannot satisfy any constraints then use it as unconstrained
                                                decrease_or(
                                                    &mut self.unconstrained_value,
                                                    CoinOrTokenId::Coin,
                                                    *coins,
                                                    IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin)
                                                )?;
                                                output_coins = Amount::ZERO;
                                            }
                                        };
                                    }
                                }
                            }
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
                                decrease_or(
                                    &mut self.unconstrained_value,
                                    CoinOrTokenId::Coin,
                                    chain_config.token_min_issuance_fee(),
                                    IOPolicyError::AttemptToViolateFeeRequirements,
                                )?;
                            }
                        },
                        OutputValue::TokenV1(token_id, amount) => decrease_or(
                            &mut self.unconstrained_value,
                            CoinOrTokenId::TokenId(*token_id),
                            *amount,
                            IOPolicyError::AttemptToPrintMoney(CoinOrTokenId::TokenId(*token_id)),
                        )?,
                    }
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use common::{
        chain::{
            config::ChainType, output_value::OutputValue, stakelock::StakePoolData,
            timelock::OutputTimeLock, AccountNonce, ConsensusUpgrade, DelegationId, Destination,
            NetUpgrades, OutPointSourceId, PoSChainConfigBuilder, PoolId, TxOutput, UtxoOutPoint,
        },
        primitives::{per_thousand::PerThousand, Amount, Id, H256},
    };
    use crypto::{
        random::{CryptoRng, Rng},
        vrf::{VRFKeyKind, VRFPrivateKey},
    };
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    fn create_stake_pool_data(
        rng: &mut (impl Rng + CryptoRng),
        atoms_to_stake: u128,
    ) -> StakePoolData {
        let (_, vrf_pub_key) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
        StakePoolData::new(
            Amount::from_atoms(atoms_to_stake),
            Destination::AnyoneCanSpend,
            vrf_pub_key,
            Destination::AnyoneCanSpend,
            PerThousand::new(0).unwrap(),
            Amount::ZERO,
        )
    }

    // Check that it's allowed to pay fees from decommissioning a pool
    // by providing smaller total outputs than inputs
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn allow_fees_from_decommission(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
            .consensus_upgrades(NetUpgrades::regtest_with_pos())
            .build();
        let required_maturity_distance =
            chain_config.staking_pool_spend_maturity_distance(BlockHeight::new(1));

        let pool_id = PoolId::new(H256::zero());
        let staked_atoms = rng.gen_range(100..1000);
        let fee_atoms = rng.gen_range(1..100);
        let stake_pool_data = create_stake_pool_data(&mut rng, staked_atoms);

        let pledge_getter = |_| Ok(Some(Amount::from_atoms(staked_atoms)));
        let delegation_balance_getter = |_| Ok(None);
        let issuance_token_id_getter = || unreachable!();

        let inputs = vec![TxInput::Utxo(UtxoOutPoint::new(
            OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
            0,
        ))];
        let input_utxos = vec![Some(TxOutput::CreateStakePool(
            pool_id,
            Box::new(stake_pool_data),
        ))];

        let outputs = vec![TxOutput::LockThenTransfer(
            OutputValue::Coin(Amount::from_atoms(staked_atoms - fee_atoms)),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(required_maturity_distance.to_int() as u64),
        )];

        let mut constraints_accumulator = ConstrainedValueAccumulator::new();

        constraints_accumulator
            .process_inputs(
                &chain_config,
                BlockHeight::new(1),
                pledge_getter,
                delegation_balance_getter,
                issuance_token_id_getter,
                &inputs,
                &input_utxos,
            )
            .unwrap();

        constraints_accumulator.process_outputs(&chain_config, &outputs).unwrap();

        assert_eq!(
            constraints_accumulator.consume().unwrap(),
            Fee(Amount::from_atoms(fee_atoms))
        );
    }

    // Check that it's allowed to pay fees from spending a delegation share
    // by providing smaller total outputs than inputs
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn allow_fees_from_spend_share(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
            .consensus_upgrades(NetUpgrades::regtest_with_pos())
            .build();
        let required_maturity_distance =
            chain_config.staking_pool_spend_maturity_distance(BlockHeight::new(1));

        let delegation_id = DelegationId::new(H256::zero());
        let delegated_atoms = rng.gen_range(100..1000);
        let fee_atoms = rng.gen_range(1..100);

        let pledge_getter = |_| Ok(None);
        let delegation_balance_getter = |_| Ok(Some(Amount::from_atoms(delegated_atoms)));
        let issuance_token_id_getter = || unreachable!();

        let inputs_utxos = vec![None];
        let inputs = vec![TxInput::from_account(
            AccountNonce::new(0),
            AccountSpending::DelegationBalance(delegation_id, Amount::from_atoms(delegated_atoms)),
        )];

        let outputs = vec![TxOutput::LockThenTransfer(
            OutputValue::Coin(Amount::from_atoms(delegated_atoms - fee_atoms)),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(required_maturity_distance.to_int() as u64),
        )];

        let mut constraints_accumulator = ConstrainedValueAccumulator::new();

        constraints_accumulator
            .process_inputs(
                &chain_config,
                BlockHeight::new(1),
                pledge_getter,
                delegation_balance_getter,
                issuance_token_id_getter,
                &inputs,
                &inputs_utxos,
            )
            .unwrap();

        constraints_accumulator.process_outputs(&chain_config, &outputs).unwrap();

        assert_eq!(
            constraints_accumulator.consume().unwrap(),
            Fee(Amount::from_atoms(fee_atoms))
        );
    }

    // Create a staking pool.
    // Try to decommission and spend a utxo in a tx. Outputs of a tx are not locked and has more coins than input utxo.
    // Check that it's a timelock violation.
    // Next decommission a pool and spend a utxo. Outputs are not locked but are equal to utxo value.
    // Check it's ok.
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn no_timelock_outputs_on_decommission(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
            .consensus_upgrades(NetUpgrades::regtest_with_pos())
            .build();

        let pool_id = PoolId::new(H256::zero());
        let staked_atoms = rng.gen_range(100..1000);
        let less_than_staked_amount = Amount::from_atoms(rng.gen_range(1..staked_atoms));
        let stake_pool_data = create_stake_pool_data(&mut rng, staked_atoms);

        let pledge_getter = |_| Ok(Some(Amount::from_atoms(staked_atoms)));
        let delegation_balance_getter = |_| Ok(None);
        let issuance_token_id_getter = || unreachable!();

        let inputs = vec![
            TxInput::from_utxo(
                OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
                0,
            ),
            TxInput::from_utxo(
                OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
                1,
            ),
        ];
        let inputs_utxos = vec![
            Some(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            )),
            Some(TxOutput::Transfer(
                OutputValue::Coin(less_than_staked_amount),
                Destination::AnyoneCanSpend,
            )),
        ];

        // it's an error if output includes staked coins
        let outputs = vec![TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(staked_atoms)),
            Destination::AnyoneCanSpend,
        )];

        {
            let mut constraints_accumulator = ConstrainedValueAccumulator::new();
            constraints_accumulator
                .process_inputs(
                    &chain_config,
                    BlockHeight::new(1),
                    pledge_getter,
                    delegation_balance_getter,
                    issuance_token_id_getter,
                    &inputs,
                    &inputs_utxos,
                )
                .unwrap();

            let result =
                constraints_accumulator.process_outputs(&chain_config, &outputs).unwrap_err();
            assert_eq!(
                result,
                IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin)
            );
        }

        // it's not an error if output does not include staked coins
        let outputs = vec![TxOutput::Transfer(
            OutputValue::Coin(less_than_staked_amount),
            Destination::AnyoneCanSpend,
        )];

        {
            let mut constraints_accumulator = ConstrainedValueAccumulator::new();
            constraints_accumulator
                .process_inputs(
                    &chain_config,
                    BlockHeight::new(1),
                    pledge_getter,
                    delegation_balance_getter,
                    issuance_token_id_getter,
                    &inputs,
                    &inputs_utxos,
                )
                .unwrap();

            constraints_accumulator.process_outputs(&chain_config, &outputs).unwrap();
        }
    }

    // Create a staking pool.
    // Try to decommission a pool by providing locked outputs with not enough block count.
    // Check it's an error.
    // Then create and check valid case.
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn try_to_unlock_coins_with_smaller_timelock(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
            .consensus_upgrades(NetUpgrades::regtest_with_pos())
            .build();
        let required_maturity_distance =
            chain_config.staking_pool_spend_maturity_distance(BlockHeight::new(1));

        let pool_id = PoolId::new(H256::zero());
        let staked_atoms = rng.gen_range(100..1000);
        let less_than_staked_amount = Amount::from_atoms(rng.gen_range(1..staked_atoms));
        let stake_pool_data = create_stake_pool_data(&mut rng, staked_atoms);

        let pledge_getter = |_| Ok(Some(Amount::from_atoms(staked_atoms)));
        let delegation_balance_getter = |_| Ok(None);
        let issuance_token_id_getter = || unreachable!();

        let inputs = vec![
            TxInput::from_utxo(
                OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
                0,
            ),
            TxInput::from_utxo(
                OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
                1,
            ),
        ];
        let inputs_utxos = vec![
            Some(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            )),
            Some(TxOutput::Transfer(
                OutputValue::Coin(less_than_staked_amount),
                Destination::AnyoneCanSpend,
            )),
        ];

        let outputs = vec![
            TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(staked_atoms - 10)),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(required_maturity_distance.to_int() as u64),
            ),
            TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(10)),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(required_maturity_distance.to_int() as u64 - 1),
            ),
            TxOutput::Transfer(
                OutputValue::Coin(less_than_staked_amount),
                Destination::AnyoneCanSpend,
            ),
        ];

        let mut constraints_accumulator = ConstrainedValueAccumulator::new();

        constraints_accumulator
            .process_inputs(
                &chain_config,
                BlockHeight::new(1),
                pledge_getter,
                delegation_balance_getter,
                issuance_token_id_getter,
                &inputs,
                &inputs_utxos,
            )
            .unwrap();

        let result = constraints_accumulator.process_outputs(&chain_config, &outputs).unwrap_err();
        assert_eq!(
            result,
            IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin)
        );

        // valid case
        let outputs = vec![
            TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(staked_atoms - 10)),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(required_maturity_distance.to_int() as u64),
            ),
            TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(10)),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(required_maturity_distance.to_int() as u64),
            ),
            TxOutput::Transfer(
                OutputValue::Coin(less_than_staked_amount),
                Destination::AnyoneCanSpend,
            ),
        ];

        {
            let mut constraints_accumulator = ConstrainedValueAccumulator::new();
            constraints_accumulator
                .process_inputs(
                    &chain_config,
                    BlockHeight::new(1),
                    pledge_getter,
                    delegation_balance_getter,
                    issuance_token_id_getter,
                    &inputs,
                    &inputs_utxos,
                )
                .unwrap();

            constraints_accumulator.process_outputs(&chain_config, &outputs).unwrap();
        }
    }

    // Create a stake pool with delegation.
    // Decommission the pool and spend delegation share in the same tx.
    // First create a tx with output where outputs are locked for the smaller block count.
    // Check an error.
    // Then check that timelock constraints can be satisfied with a single output in a valid case.
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn check_timelock_saturation(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let required_decommission_maturity = 100;
        let required_spend_share_maturity = 200;
        let upgrades = vec![(
            BlockHeight::new(0),
            ConsensusUpgrade::PoS {
                initial_difficulty: None,
                config: PoSChainConfigBuilder::new_for_unit_test()
                    .staking_pool_spend_maturity_distance(required_decommission_maturity.into())
                    .staking_pool_spend_maturity_distance(required_spend_share_maturity.into())
                    .build(),
            },
        )];
        let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
        let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
            .consensus_upgrades(net_upgrades)
            .build();

        let pool_id = PoolId::new(H256::zero());
        let staked_atoms = rng.gen_range(100..1000);
        let stake_pool_data = create_stake_pool_data(&mut rng, staked_atoms);

        let delegation_id = DelegationId::new(H256::zero());
        let delegated_atoms = rng.gen_range(1..1000);

        let transferred_atoms = rng.gen_range(100..1000);

        let pledge_getter = |_| Ok(Some(Amount::from_atoms(staked_atoms)));
        let delegation_balance_getter = |_| Ok(Some(Amount::from_atoms(delegated_atoms)));
        let issuance_token_id_getter = || unreachable!();

        let inputs = vec![
            TxInput::from_utxo(
                OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
                0,
            ),
            TxInput::from_utxo(
                OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
                1,
            ),
            TxInput::from_account(
                AccountNonce::new(0),
                AccountSpending::DelegationBalance(
                    delegation_id,
                    Amount::from_atoms(delegated_atoms),
                ),
            ),
        ];
        let inputs_utxos = vec![
            Some(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            )),
            Some(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(transferred_atoms)),
                Destination::AnyoneCanSpend,
            )),
            None,
        ];

        let outputs = vec![
            TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(staked_atoms + delegated_atoms)),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(
                    required_decommission_maturity as u64 + required_spend_share_maturity as u64
                        - 1,
                ),
            ),
            TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(transferred_atoms)),
                Destination::AnyoneCanSpend,
            ),
        ];

        let mut constraints_accumulator = ConstrainedValueAccumulator::new();
        let result = constraints_accumulator.process_outputs(&chain_config, &outputs).unwrap_err();
        assert_eq!(
            result,
            IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin)
        );

        // valid case
        let outputs = vec![
            TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(staked_atoms + delegated_atoms)),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(
                    required_decommission_maturity as u64 + required_spend_share_maturity as u64,
                ),
            ),
            TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(transferred_atoms)),
                Destination::AnyoneCanSpend,
            ),
        ];

        let mut constraints_accumulator = ConstrainedValueAccumulator::new();

        constraints_accumulator
            .process_inputs(
                &chain_config,
                BlockHeight::new(1),
                pledge_getter,
                delegation_balance_getter,
                issuance_token_id_getter,
                &inputs,
                &inputs_utxos,
            )
            .unwrap();

        constraints_accumulator.process_outputs(&chain_config, &outputs).unwrap();

        assert_eq!(
            constraints_accumulator.consume().unwrap(),
            Fee(Amount::ZERO)
        );
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn try_to_overspend_on_spending_delegation(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
            .consensus_upgrades(NetUpgrades::regtest_with_pos())
            .build();

        let delegation_id = DelegationId::new(H256::zero());
        let delegation_balance = Amount::from_atoms(rng.gen_range(100..1000));

        let pledge_getter = |_| Ok(None);
        let delegation_balance_getter = |_| Ok(Some(delegation_balance));
        let issuance_token_id_getter = || unreachable!();

        // it's an error to spend more the balance
        let inputs = vec![TxInput::from_account(
            AccountNonce::new(0),
            AccountSpending::DelegationBalance(
                delegation_id,
                (delegation_balance + Amount::from_atoms(1)).unwrap(),
            ),
        )];
        let inputs_utxos = vec![None];

        {
            let mut constraints_accumulator = ConstrainedValueAccumulator::new();
            let result = constraints_accumulator.process_inputs(
                &chain_config,
                BlockHeight::new(1),
                pledge_getter,
                delegation_balance_getter,
                issuance_token_id_getter,
                &inputs,
                &inputs_utxos,
            );

            assert_eq!(
                result.unwrap_err(),
                IOPolicyError::AttemptToPrintMoney(CoinOrTokenId::Coin)
            );
        }

        // it's not an error to spend <= balance
        let inputs = vec![TxInput::from_account(
            AccountNonce::new(0),
            AccountSpending::DelegationBalance(delegation_id, delegation_balance),
        )];
        let outputs = vec![TxOutput::LockThenTransfer(
            OutputValue::Coin(delegation_balance),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(
                chain_config.spend_share_maturity_distance(BlockHeight::new(1)).to_int() as u64,
            ),
        )];

        {
            let mut constraints_accumulator = ConstrainedValueAccumulator::new();
            constraints_accumulator
                .process_inputs(
                    &chain_config,
                    BlockHeight::new(1),
                    pledge_getter,
                    delegation_balance_getter,
                    issuance_token_id_getter,
                    &inputs,
                    &inputs_utxos,
                )
                .unwrap();

            constraints_accumulator.process_outputs(&chain_config, &outputs).unwrap();
        }
    }
}
