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

use std::collections::BTreeMap;

use common::{
    chain::{
        output_value::OutputValue, timelock::OutputTimeLock, tokens::TokenData, AccountOp,
        ChainConfig, PoolId, TxInput, TxOutput,
    },
    primitives::{Amount, BlockDistance, BlockHeight},
};
use utils::ensure;

use super::IOPolicyError;

/// `ConstrainedValueAccumulator` helps avoiding messy inputs/outputs combinations analysis by
/// providing a set of properties that should be satisfied. For example instead of checking that
/// all outputs are timelocked when the pool is decommissioned `ConstrainedValueAccumulator` gives a way
/// to check that an accumulated output value is locked for sufficient amount of time which allows
/// using other valid inputs and outputs in the same tx.
///
/// TODO: this struct can be extended to collect tokens replacing `AmountsMap`
pub struct ConstrainedValueAccumulator {
    unconstrained_value: Amount,
    timelock_constrained: BTreeMap<BlockDistance, Amount>,
    token_fee_burn_constrained: Amount,
}

impl ConstrainedValueAccumulator {
    pub fn new() -> Self {
        Self {
            unconstrained_value: Amount::ZERO,
            timelock_constrained: Default::default(),
            token_fee_burn_constrained: Amount::ZERO,
        }
    }

    /// Return accumulated amounts that are left
    // TODO: for now only used in tests but can be used to calculate fees
    #[allow(dead_code)]
    pub fn consume(self) -> Result<Amount, IOPolicyError> {
        self.timelock_constrained
            .into_values()
            .sum::<Option<Amount>>()
            .and_then(|v| v + self.unconstrained_value)
            .ok_or(IOPolicyError::AmountOverflow)
    }

    pub fn process_inputs<PledgeAmountGetterFn>(
        &mut self,
        chain_config: &ChainConfig,
        block_height: BlockHeight,
        pledge_amount_getter: PledgeAmountGetterFn,
        inputs: &[TxInput],
        inputs_utxos: &[Option<TxOutput>],
    ) -> Result<(), IOPolicyError>
    where
        PledgeAmountGetterFn: Fn(PoolId) -> Result<Option<Amount>, IOPolicyError>,
    {
        ensure!(
            inputs.len() == inputs_utxos.len(),
            IOPolicyError::InputsAndInputsUtxosLengthMismatch(inputs.len(), inputs_utxos.len())
        );

        for (input, input_utxo) in inputs.iter().zip(inputs_utxos.iter()) {
            match input {
                TxInput::Utxo(outpoint) => {
                    match input_utxo
                        .as_ref()
                        .ok_or(IOPolicyError::MissingOutputOrSpent(outpoint.clone()))?
                    {
                        TxOutput::Transfer(value, _) | TxOutput::LockThenTransfer(value, _, _) => {
                            if let Some(coins) = value.coin_amount() {
                                self.unconstrained_value = (self.unconstrained_value + coins)
                                    .ok_or(IOPolicyError::AmountOverflow)?;
                            }
                        }
                        TxOutput::DelegateStaking(coins, _) => {
                            self.unconstrained_value = (self.unconstrained_value + *coins)
                                .ok_or(IOPolicyError::AmountOverflow)?;
                        }
                        TxOutput::CreateDelegationId(..)
                        | TxOutput::IssueFungibleToken(..)
                        | TxOutput::Burn(..) => return Err(IOPolicyError::NotSpendableInputType),
                        TxOutput::IssueNft(..) => { /* TODO: support tokens */ }
                        TxOutput::CreateStakePool(pool_id, _)
                        | TxOutput::ProduceBlockFromStake(_, pool_id) => {
                            let block_distance = chain_config
                                .as_ref()
                                .decommission_pool_maturity_distance(block_height);
                            let pledged_amount = pledge_amount_getter(*pool_id)?
                                .ok_or(IOPolicyError::PledgeAmountNotFound(*pool_id))?;

                            let balance = self
                                .timelock_constrained
                                .entry(block_distance)
                                .or_insert(Amount::ZERO);
                            *balance =
                                (*balance + pledged_amount).ok_or(IOPolicyError::AmountOverflow)?;
                        }
                    };
                }
                TxInput::Account(account) => {
                    match account.account() {
                        AccountOp::SpendDelegationBalance(_, spend_amount) => {
                            let block_distance =
                                chain_config.as_ref().spend_share_maturity_distance(block_height);

                            let balance = self
                                .timelock_constrained
                                .entry(block_distance)
                                .or_insert(Amount::ZERO);
                            *balance =
                                (*balance + *spend_amount).ok_or(IOPolicyError::AmountOverflow)?;
                        }
                        AccountOp::MintTokens(_, _)
                        | AccountOp::LockTokenSupply(_)
                        | AccountOp::UnmintTokens(_) => {
                            let fee = chain_config.as_ref().token_min_supply_change_fee();
                            self.token_fee_burn_constrained = (self.token_fee_burn_constrained
                                + fee)
                                .ok_or(IOPolicyError::AmountOverflow)?;
                        }
                    };
                }
            }
        }
        Ok(())
    }

    pub fn process_outputs(
        &mut self,
        chain_config: &ChainConfig,
        outputs: &[TxOutput],
    ) -> Result<(), IOPolicyError> {
        let mut total_burned = Amount::ZERO;

        for output in outputs {
            match output {
                TxOutput::Transfer(value, _) => match value {
                    OutputValue::Coin(coins) => {
                        self.unconstrained_value = (self.unconstrained_value - *coins).ok_or(
                            IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints,
                        )?;
                    }
                    OutputValue::TokenV0(token_data) => match token_data.as_ref() {
                        TokenData::TokenTransfer(_) => { /* do nothing */ }
                        TokenData::TokenIssuance(_) | TokenData::NftIssuance(_) => {
                            let fee = chain_config.as_ref().token_min_issuance_fee();
                            self.token_fee_burn_constrained = (self.token_fee_burn_constrained
                                + fee)
                                .ok_or(IOPolicyError::AmountOverflow)?;
                        }
                    },
                    OutputValue::TokenV1(_, _) => { /* do nothing */ }
                },
                TxOutput::Burn(value) => match value {
                    OutputValue::Coin(coins) => {
                        total_burned =
                            (total_burned + *coins).ok_or(IOPolicyError::AmountOverflow)?
                    }
                    OutputValue::TokenV0(token_data) => match token_data.as_ref() {
                        TokenData::TokenTransfer(_) => { /* do nothing */ }
                        TokenData::TokenIssuance(_) | TokenData::NftIssuance(_) => {
                            let fee = chain_config.as_ref().token_min_issuance_fee();
                            self.token_fee_burn_constrained = (self.token_fee_burn_constrained
                                + fee)
                                .ok_or(IOPolicyError::AmountOverflow)?;
                        }
                    },
                    OutputValue::TokenV1(_, _) => { /* do nothing */ }
                },
                TxOutput::DelegateStaking(coins, _) => {
                    self.unconstrained_value = (self.unconstrained_value - *coins)
                        .ok_or(IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints)?;
                }
                TxOutput::CreateStakePool(_, data) => {
                    self.unconstrained_value = (self.unconstrained_value - data.value())
                        .ok_or(IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints)?;
                }
                TxOutput::ProduceBlockFromStake(_, _) | TxOutput::CreateDelegationId(_, _) => {
                    /* do nothing as these outputs cannot produce values */
                }
                TxOutput::LockThenTransfer(value, _, timelock) => match timelock {
                    OutputTimeLock::UntilHeight(_)
                    | OutputTimeLock::UntilTime(_)
                    | OutputTimeLock::ForSeconds(_) => { /* do nothing */ }
                    OutputTimeLock::ForBlockCount(block_count) => {
                        if let Some(mut coins) = value.coin_amount() {
                            let block_count: i64 = (*block_count)
                                .try_into()
                                .map_err(|_| IOPolicyError::BlockHeightArithmeticError)?;
                            let distance = BlockDistance::from(block_count);

                            // find the range that can be saturated with the current timelock
                            let range = self.timelock_constrained.range_mut((
                                std::ops::Bound::Unbounded,
                                std::ops::Bound::Included(distance),
                            ));

                            let mut range_iter = range.rev().peekable();

                            // subtract output coins from constrained values starting from max until all coins are used
                            while coins > Amount::ZERO {
                                match range_iter.peek_mut() {
                                    Some((_, locked_coins)) => {
                                        if coins > **locked_coins {
                                            // use up current constraint and move on to the next one
                                            coins = (coins - **locked_coins).expect("cannot fail");
                                            **locked_coins = Amount::ZERO;
                                            range_iter.next();
                                        } else {
                                            **locked_coins =
                                                (**locked_coins - coins).expect("cannot fail");
                                            coins = Amount::ZERO;
                                        }
                                    }
                                    None => {
                                        // if lock cannot satisfy any constraints then use it as unconstrained
                                        self.unconstrained_value =
                                        (self.unconstrained_value - coins)
                                            .ok_or(IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints)?;
                                        coins = Amount::ZERO;
                                    }
                                };
                            }
                        }
                    }
                },
                TxOutput::IssueFungibleToken(_) | TxOutput::IssueNft(_, _, _) => {
                    let fee = chain_config.as_ref().token_min_issuance_fee();
                    self.token_fee_burn_constrained = (self.token_fee_burn_constrained + fee)
                        .ok_or(IOPolicyError::AmountOverflow)?;
                }
            };
        }

        // Amount cannot be negative so burn constrains must be checked after iterating over all outputs
        ensure!(
            self.token_fee_burn_constrained <= total_burned,
            IOPolicyError::AttemptViolateTokenFeeBurnConstraints
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{
        chain::{
            config::ChainType,
            output_value::OutputValue,
            stakelock::StakePoolData,
            timelock::OutputTimeLock,
            tokens::{NftIssuance, TokenId, TokenIssuance},
            AccountNonce, AccountOp, ConsensusUpgrade, DelegationId, Destination, NetUpgrades,
            OutPointSourceId, PoSChainConfigBuilder, PoolId, TxOutput, UtxoOutPoint,
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
            chain_config.decommission_pool_maturity_distance(BlockHeight::new(1));

        let pool_id = PoolId::new(H256::zero());
        let staked_atoms = rng.gen_range(100..1000);
        let fee_atoms = rng.gen_range(1..100);
        let stake_pool_data = create_stake_pool_data(&mut rng, staked_atoms);

        let pledge_getter = |_| Ok(Some(Amount::from_atoms(staked_atoms)));

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
                &inputs,
                &input_utxos,
            )
            .unwrap();

        constraints_accumulator.process_outputs(&chain_config, &outputs).unwrap();

        assert_eq!(
            constraints_accumulator.consume().unwrap().into_atoms(),
            fee_atoms
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
            chain_config.spend_share_maturity_distance(BlockHeight::new(1));

        let delegation_id = DelegationId::new(H256::zero());
        let delegated_atoms = rng.gen_range(100..1000);
        let fee_atoms = rng.gen_range(1..100);

        let pledge_getter = |_| Ok(None);

        let inputs_utxos = vec![None];
        let inputs = vec![TxInput::from_account(
            AccountNonce::new(0),
            AccountOp::SpendDelegationBalance(delegation_id, Amount::from_atoms(delegated_atoms)),
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
                &inputs,
                &inputs_utxos,
            )
            .unwrap();

        constraints_accumulator.process_outputs(&chain_config, &outputs).unwrap();

        assert_eq!(
            constraints_accumulator.consume().unwrap().into_atoms(),
            fee_atoms
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
                    &inputs,
                    &inputs_utxos,
                )
                .unwrap();

            let result =
                constraints_accumulator.process_outputs(&chain_config, &outputs).unwrap_err();
            assert_eq!(
                result,
                IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints
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
            chain_config.decommission_pool_maturity_distance(BlockHeight::new(1));

        let pool_id = PoolId::new(H256::zero());
        let staked_atoms = rng.gen_range(100..1000);
        let less_than_staked_amount = Amount::from_atoms(rng.gen_range(1..staked_atoms));
        let stake_pool_data = create_stake_pool_data(&mut rng, staked_atoms);

        let pledge_getter = |_| Ok(Some(Amount::from_atoms(staked_atoms)));

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
                &inputs,
                &inputs_utxos,
            )
            .unwrap();

        let result = constraints_accumulator.process_outputs(&chain_config, &outputs).unwrap_err();
        assert_eq!(
            result,
            IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints
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
                    .decommission_maturity_distance(required_decommission_maturity.into())
                    .spend_share_maturity_distance(required_spend_share_maturity.into())
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
                AccountOp::SpendDelegationBalance(
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
            IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints
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
                &inputs,
                &inputs_utxos,
            )
            .unwrap();

        constraints_accumulator.process_outputs(&chain_config, &outputs).unwrap();

        assert_eq!(constraints_accumulator.consume().unwrap(), Amount::ZERO);
    }

    // Create a custom inputs/outputs set with 6 supply changes and 4 issuances of different kind.
    // Check that burn constraints are satisfied.
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn token_fee_burn(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let chain_config = common::chain::config::Builder::new(ChainType::Mainnet).build();
        let token_min_issuance_fee = chain_config.token_min_issuance_fee();
        let token_min_change_supply_fee = chain_config.token_min_supply_change_fee();

        let token_id = TokenId::new(H256::zero());
        let amount_to_mint = Amount::from_atoms(rng.gen_range(100..1000));

        let fungible_token_v0_issuance =
            test_utils::nft_utils::random_token_issuance(&chain_config, &mut rng);
        let fungible_token_v1_issuance =
            test_utils::nft_utils::random_token_issuance_v1(&chain_config, &mut rng);
        let nft_v1_issuance_1 = test_utils::nft_utils::random_nft_issuance(&chain_config, &mut rng);
        let nft_v1_issuance_2 = test_utils::nft_utils::random_nft_issuance(&chain_config, &mut rng);
        let nft_v1_issuance_3 = test_utils::nft_utils::random_nft_issuance(&chain_config, &mut rng);

        let source_id = OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng)));
        let inputs = vec![
            TxInput::from_account(
                AccountNonce::new(0),
                AccountOp::MintTokens(token_id, amount_to_mint),
            ),
            TxInput::from_account(AccountNonce::new(0), AccountOp::UnmintTokens(token_id)),
            TxInput::from_account(AccountNonce::new(0), AccountOp::LockTokenSupply(token_id)),
            TxInput::from_account(AccountNonce::new(0), AccountOp::UnmintTokens(token_id)),
            TxInput::from_utxo(source_id.clone(), 0),
            TxInput::from_account(AccountNonce::new(0), AccountOp::LockTokenSupply(token_id)),
            TxInput::from_utxo(source_id, 0),
            TxInput::from_account(
                AccountNonce::new(0),
                AccountOp::MintTokens(token_id, amount_to_mint),
            ),
        ];
        let input_utxos = vec![
            None,
            None,
            None,
            None,
            Some(TxOutput::Transfer(
                OutputValue::Coin((token_min_issuance_fee * 4).unwrap()),
                Destination::AnyoneCanSpend,
            )),
            None,
            Some(TxOutput::Transfer(
                OutputValue::Coin((token_min_change_supply_fee * 6).unwrap()),
                Destination::AnyoneCanSpend,
            )),
            None,
        ];

        let outputs = vec![
            TxOutput::Burn(OutputValue::Coin(
                (token_min_issuance_fee + token_min_change_supply_fee).unwrap(),
            )),
            TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(fungible_token_v1_issuance))),
            TxOutput::IssueNft(
                token_id,
                Box::new(NftIssuance::V0(nft_v1_issuance_1)),
                Destination::AnyoneCanSpend,
            ),
            TxOutput::Burn(OutputValue::Coin((token_min_issuance_fee * 2).unwrap())),
            TxOutput::Burn(OutputValue::Coin(
                (token_min_change_supply_fee * 2).unwrap(),
            )),
            TxOutput::Transfer(
                OutputValue::TokenV0(Box::new(fungible_token_v0_issuance.into())),
                Destination::AnyoneCanSpend,
            ),
            TxOutput::LockThenTransfer(
                OutputValue::TokenV0(Box::new(nft_v1_issuance_2.into())),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ),
            TxOutput::Burn(OutputValue::Coin(
                (token_min_change_supply_fee * 3).unwrap(),
            )),
            TxOutput::Burn(OutputValue::TokenV0(Box::new(nft_v1_issuance_3.into()))),
            TxOutput::Burn(OutputValue::Coin(token_min_issuance_fee)),
        ];

        let pledge_getter = |_| unreachable!();

        let mut constraints_accumulator = ConstrainedValueAccumulator::new();
        constraints_accumulator
            .process_inputs(
                &chain_config,
                BlockHeight::new(1),
                pledge_getter,
                &inputs,
                &input_utxos,
            )
            .unwrap();

        constraints_accumulator.process_outputs(&chain_config, &outputs).unwrap();
    }
}
