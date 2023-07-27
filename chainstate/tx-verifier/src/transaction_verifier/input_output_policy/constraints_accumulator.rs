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
    chain::{timelock::OutputTimeLock, AccountSpending, ChainConfig, PoolId, TxInput, TxOutput},
    primitives::{Amount, BlockDistance, BlockHeight},
};
use utils::ensure;

use crate::error::ConnectTransactionError;

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
}

impl ConstrainedValueAccumulator {
    pub fn new() -> Self {
        Self {
            unconstrained_value: Amount::ZERO,
            timelock_constrained: Default::default(),
        }
    }

    /// Return accumulated amounts that are left
    // TODO: for now only used in tests but can be used to calculate fees
    #[allow(dead_code)]
    pub fn consume(self) -> Result<Amount, IOPolicyError> {
        self.timelock_constrained
            .values()
            .copied()
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
    ) -> Result<(), ConnectTransactionError>
    where
        PledgeAmountGetterFn: Fn(PoolId) -> Result<Amount, ConnectTransactionError>,
    {
        ensure!(
            inputs.len() == inputs_utxos.len(),
            IOPolicyError::InputsAndInputsUtxosLengthMismatch(inputs.len(), inputs_utxos.len())
        );

        for (input, input_utxo) in inputs.iter().zip(inputs_utxos.iter()) {
            match input {
                TxInput::Utxo(_) => {
                    match input_utxo
                        .as_ref()
                        .ok_or(ConnectTransactionError::MissingOutputOrSpent)?
                    {
                        TxOutput::Transfer(value, _)
                        | TxOutput::LockThenTransfer(value, _, _)
                        | TxOutput::Burn(value) => {
                            if let Some(coins) = value.coin_amount() {
                                self.unconstrained_value = (self.unconstrained_value + coins)
                                    .ok_or(IOPolicyError::AmountOverflow)?;
                            }
                        }
                        TxOutput::DelegateStaking(coins, _) => {
                            self.unconstrained_value = (self.unconstrained_value + *coins)
                                .ok_or(IOPolicyError::AmountOverflow)?;
                        }
                        TxOutput::CreateDelegationId(..) => { /* do nothing */ }
                        TxOutput::CreateStakePool(pool_id, _)
                        | TxOutput::ProduceBlockFromStake(_, pool_id) => {
                            let block_distance = chain_config
                                .as_ref()
                                .decommission_pool_maturity_distance(block_height);
                            let pledged_amount = pledge_amount_getter(*pool_id)?;
                            match self.timelock_constrained.entry(block_distance) {
                                Entry::Vacant(e) => {
                                    e.insert(pledged_amount);
                                }
                                Entry::Occupied(mut e) => {
                                    let new_balance = (*e.get() + pledged_amount)
                                        .ok_or(IOPolicyError::AmountOverflow)?;
                                    *e.get_mut() = new_balance;
                                }
                            };
                        }
                    };
                }
                TxInput::Account(account) => {
                    match account.account() {
                        AccountSpending::Delegation(_, spend_amount) => {
                            let block_distance =
                                chain_config.as_ref().spend_share_maturity_distance(block_height);
                            match self.timelock_constrained.entry(block_distance) {
                                Entry::Vacant(e) => {
                                    e.insert(*spend_amount);
                                }
                                Entry::Occupied(mut e) => {
                                    let new_balance = (*e.get() + *spend_amount)
                                        .ok_or(IOPolicyError::AmountOverflow)?;
                                    *e.get_mut() = new_balance;
                                }
                            };
                        }
                    };
                }
            }
        }
        Ok(())
    }

    pub fn process_outputs(&mut self, outputs: &[TxOutput]) -> Result<(), ConnectTransactionError> {
        for output in outputs {
            match output {
                TxOutput::Transfer(value, _) | TxOutput::Burn(value) => {
                    if let Some(coins) = value.coin_amount() {
                        self.unconstrained_value = (self.unconstrained_value - coins).ok_or(
                            IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints,
                        )?;
                    }
                }
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
                                .map_err(|_| ConnectTransactionError::BlockHeightArithmeticError)?;
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
            };
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{
        chain::{
            config::ChainType, stakelock::StakePoolData, timelock::OutputTimeLock,
            tokens::OutputValue, AccountNonce, AccountSpending, ConsensusUpgrade, DelegationId,
            Destination, NetUpgrades, OutPointSourceId, PoSChainConfig, PoolId, TxOutput,
            UpgradeVersion, UtxoOutPoint,
        },
        primitives::{per_thousand::PerThousand, Amount, Id, H256},
        Uint256,
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

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn allow_fees_from_decommission(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
            .net_upgrades(NetUpgrades::regtest_with_pos())
            .build();
        let required_maturity_distance =
            chain_config.decommission_pool_maturity_distance(BlockHeight::new(1));

        let pool_id = PoolId::new(H256::zero());
        let staked_atoms = rng.gen_range(100..1000);
        let fee_atoms = rng.gen_range(1..100);
        let stake_pool_data = create_stake_pool_data(&mut rng, staked_atoms);

        let pledge_getter = |_| Ok(Amount::from_atoms(staked_atoms));

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
            OutputTimeLock::ForBlockCount(required_maturity_distance.into_int() as u64),
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

        constraints_accumulator.process_outputs(&outputs).unwrap();

        assert_eq!(
            constraints_accumulator.consume().unwrap().into_atoms(),
            fee_atoms
        );
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn allow_fees_from_spend_share(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
            .net_upgrades(NetUpgrades::regtest_with_pos())
            .build();
        let required_maturity_distance =
            chain_config.spend_share_maturity_distance(BlockHeight::new(1));

        let delegation_id = DelegationId::new(H256::zero());
        let delegated_atoms = rng.gen_range(100..1000);
        let fee_atoms = rng.gen_range(1..100);

        let pledge_getter = |_| Ok(Amount::ZERO);

        let inputs_utxos = vec![None];
        let inputs = vec![TxInput::from_account(
            AccountNonce::new(0),
            AccountSpending::Delegation(delegation_id, Amount::from_atoms(delegated_atoms)),
        )];

        let outputs = vec![TxOutput::LockThenTransfer(
            OutputValue::Coin(Amount::from_atoms(delegated_atoms - fee_atoms)),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(required_maturity_distance.into_int() as u64),
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

        constraints_accumulator.process_outputs(&outputs).unwrap();

        assert_eq!(
            constraints_accumulator.consume().unwrap().into_atoms(),
            fee_atoms
        );
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn try_to_unlocked_coins(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
            .net_upgrades(NetUpgrades::regtest_with_pos())
            .build();
        let required_maturity_distance =
            chain_config.decommission_pool_maturity_distance(BlockHeight::new(1));

        let pool_id = PoolId::new(H256::zero());
        let staked_atoms = rng.gen_range(100..1000);
        let stake_pool_data = create_stake_pool_data(&mut rng, staked_atoms);

        let pledge_getter = |_| Ok(Amount::from_atoms(staked_atoms));

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
                OutputValue::Coin(Amount::from_atoms(100)),
                Destination::AnyoneCanSpend,
            )),
        ];

        let outputs = vec![
            TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(staked_atoms - 10)),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(required_maturity_distance.into_int() as u64),
            ),
            TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(10)),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(required_maturity_distance.into_int() as u64 - 1),
            ),
            TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(100)),
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

        let result = constraints_accumulator.process_outputs(&outputs).unwrap_err();
        assert_eq!(
            result,
            ConnectTransactionError::IOPolicyError(
                IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints
            )
        );
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn check_timelock_saturation(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let required_decommission_maturity = 100;
        let required_spend_share_maturity = 200;
        let upgrades = vec![(
            BlockHeight::new(0),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                initial_difficulty: Uint256::MAX.into(),
                config: PoSChainConfig::new(
                    Uint256::MAX,
                    1,
                    required_decommission_maturity.into(),
                    required_spend_share_maturity.into(),
                    2,
                    PerThousand::new(0).unwrap(),
                )
                .unwrap(),
            }),
        )];
        let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
        let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
            .net_upgrades(net_upgrades)
            .build();

        let pool_id = PoolId::new(H256::zero());
        let staked_atoms = rng.gen_range(100..1000);
        let stake_pool_data = create_stake_pool_data(&mut rng, staked_atoms);

        let delegation_id = DelegationId::new(H256::zero());
        let delegated_atoms = rng.gen_range(1..1000);

        let transferred_atoms = rng.gen_range(100..1000);

        let pledge_getter = |_| Ok(Amount::from_atoms(staked_atoms));

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
                AccountSpending::Delegation(delegation_id, Amount::from_atoms(delegated_atoms)),
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

        constraints_accumulator.process_outputs(&outputs).unwrap();

        assert_eq!(constraints_accumulator.consume().unwrap(), Amount::ZERO);
    }
}
