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

use std::{collections::BTreeMap, ops::Range};

use common::{
    chain::{
        config::ChainType, output_value::OutputValue, stakelock::StakePoolData,
        timelock::OutputTimeLock, AccountNonce, AccountSpending, ConsensusUpgrade, Destination,
        NetUpgrades, PoSChainConfigBuilder, PoolId, TxOutput,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockCount, H256},
};
use crypto::{
    random::{CryptoRng, Rng, SliceRandom},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use rstest::rstest;
use test_utils::{
    random::{make_seedable_rng, Seed},
    split_value,
};

use super::outputs_utils::*;
use super::*;

fn random_input_utxos(
    rng: &mut impl Rng,
    total_input_atoms: u128,
    timelock_range: Range<u64>,
) -> Vec<TxOutput> {
    split_value(rng, total_input_atoms)
        .into_iter()
        .map(|v| {
            if rng.gen::<bool>() {
                TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(v)),
                    Destination::AnyoneCanSpend,
                )
            } else {
                let lock = rng.gen_range(timelock_range.clone());
                TxOutput::LockThenTransfer(
                    OutputValue::Coin(Amount::from_atoms(v)),
                    Destination::AnyoneCanSpend,
                    OutputTimeLock::ForBlockCount(lock),
                )
            }
        })
        .collect()
}

fn create_stake_pool_data(rng: &mut (impl Rng + CryptoRng), atoms_to_stake: u128) -> StakePoolData {
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
    let block_height = BlockHeight::new(1);
    let required_maturity_distance =
        chain_config.staking_pool_spend_maturity_block_count(block_height);

    let pool_id = PoolId::new(H256::zero());
    let staked_atoms = rng.gen_range(100..1000);
    let fee_atoms = rng.gen_range(1..100);
    let stake_pool_data = create_stake_pool_data(&mut rng, staked_atoms);

    let pledge_getter = |_| Ok(Some(Amount::from_atoms(staked_atoms)));
    let delegation_balance_getter = |_| Ok(None);
    let issuance_token_id_getter = |_| unreachable!();

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
        OutputTimeLock::ForBlockCount(required_maturity_distance.to_int()),
    )];

    let mut constraints_accumulator = constraints_accumulator::ConstrainedValueAccumulator::new();

    constraints_accumulator
        .process_inputs(
            &chain_config,
            block_height,
            pledge_getter,
            delegation_balance_getter,
            issuance_token_id_getter,
            &inputs,
            &input_utxos,
        )
        .unwrap();

    constraints_accumulator
        .process_outputs(&chain_config, block_height, &outputs)
        .unwrap();

    assert_eq!(
        constraints_accumulator
            .consume()
            .calculate_fee(&chain_config, block_height)
            .unwrap(),
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
    let block_height = BlockHeight::new(1);
    let required_maturity_distance =
        chain_config.staking_pool_spend_maturity_block_count(block_height);

    let delegation_id = DelegationId::new(H256::zero());
    let delegated_atoms = rng.gen_range(100..1000);
    let fee_atoms = rng.gen_range(1..100);

    let pledge_getter = |_| Ok(None);
    let delegation_balance_getter = |_| Ok(Some(Amount::from_atoms(delegated_atoms)));
    let issuance_token_id_getter = |_| unreachable!();

    let inputs_utxos = vec![None];
    let inputs = vec![TxInput::from_account(
        AccountNonce::new(0),
        AccountSpending::DelegationBalance(delegation_id, Amount::from_atoms(delegated_atoms)),
    )];

    let outputs = vec![TxOutput::LockThenTransfer(
        OutputValue::Coin(Amount::from_atoms(delegated_atoms - fee_atoms)),
        Destination::AnyoneCanSpend,
        OutputTimeLock::ForBlockCount(required_maturity_distance.to_int()),
    )];

    let mut constraints_accumulator = constraints_accumulator::ConstrainedValueAccumulator::new();

    constraints_accumulator
        .process_inputs(
            &chain_config,
            block_height,
            pledge_getter,
            delegation_balance_getter,
            issuance_token_id_getter,
            &inputs,
            &inputs_utxos,
        )
        .unwrap();

    constraints_accumulator
        .process_outputs(&chain_config, block_height, &outputs)
        .unwrap();

    assert_eq!(
        constraints_accumulator
            .consume()
            .calculate_fee(&chain_config, block_height)
            .unwrap(),
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
    let block_height = BlockHeight::new(1);

    let pool_id = PoolId::new(H256::zero());
    let staked_atoms = rng.gen_range(100..1000);
    let less_than_staked_amount = Amount::from_atoms(rng.gen_range(1..staked_atoms));
    let stake_pool_data = create_stake_pool_data(&mut rng, staked_atoms);

    let pledge_getter = |_| Ok(Some(Amount::from_atoms(staked_atoms)));
    let delegation_balance_getter = |_| Ok(None);
    let issuance_token_id_getter = |_| unreachable!();

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
        let mut constraints_accumulator =
            constraints_accumulator::ConstrainedValueAccumulator::new();
        constraints_accumulator
            .process_inputs(
                &chain_config,
                block_height,
                pledge_getter,
                delegation_balance_getter,
                issuance_token_id_getter,
                &inputs,
                &inputs_utxos,
            )
            .unwrap();

        let result = constraints_accumulator
            .process_outputs(&chain_config, block_height, &outputs)
            .unwrap_err();
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
        let mut constraints_accumulator =
            constraints_accumulator::ConstrainedValueAccumulator::new();
        constraints_accumulator
            .process_inputs(
                &chain_config,
                block_height,
                pledge_getter,
                delegation_balance_getter,
                issuance_token_id_getter,
                &inputs,
                &inputs_utxos,
            )
            .unwrap();

        constraints_accumulator
            .process_outputs(&chain_config, block_height, &outputs)
            .unwrap();
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
    let block_height = BlockHeight::new(1);
    let required_maturity_distance =
        chain_config.staking_pool_spend_maturity_block_count(block_height);

    let pool_id = PoolId::new(H256::zero());
    let staked_atoms = rng.gen_range(100..1000);
    let less_than_staked_amount = Amount::from_atoms(rng.gen_range(1..staked_atoms));
    let stake_pool_data = create_stake_pool_data(&mut rng, staked_atoms);

    let pledge_getter = |_| Ok(Some(Amount::from_atoms(staked_atoms)));
    let delegation_balance_getter = |_| Ok(None);
    let issuance_token_id_getter = |_| unreachable!();

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
            OutputTimeLock::ForBlockCount(required_maturity_distance.to_int()),
        ),
        TxOutput::LockThenTransfer(
            OutputValue::Coin(Amount::from_atoms(10)),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(required_maturity_distance.to_int() - 1),
        ),
        TxOutput::Transfer(
            OutputValue::Coin(less_than_staked_amount),
            Destination::AnyoneCanSpend,
        ),
    ];

    let mut constraints_accumulator = constraints_accumulator::ConstrainedValueAccumulator::new();

    constraints_accumulator
        .process_inputs(
            &chain_config,
            block_height,
            pledge_getter,
            delegation_balance_getter,
            issuance_token_id_getter,
            &inputs,
            &inputs_utxos,
        )
        .unwrap();

    let result = constraints_accumulator
        .process_outputs(&chain_config, block_height, &outputs)
        .unwrap_err();
    assert_eq!(
        result,
        IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin)
    );

    // valid case
    let outputs = vec![
        TxOutput::LockThenTransfer(
            OutputValue::Coin(Amount::from_atoms(staked_atoms - 10)),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(required_maturity_distance.to_int()),
        ),
        TxOutput::LockThenTransfer(
            OutputValue::Coin(Amount::from_atoms(10)),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(required_maturity_distance.to_int()),
        ),
        TxOutput::Transfer(
            OutputValue::Coin(less_than_staked_amount),
            Destination::AnyoneCanSpend,
        ),
    ];

    {
        let mut constraints_accumulator =
            constraints_accumulator::ConstrainedValueAccumulator::new();
        constraints_accumulator
            .process_inputs(
                &chain_config,
                block_height,
                pledge_getter,
                delegation_balance_getter,
                issuance_token_id_getter,
                &inputs,
                &inputs_utxos,
            )
            .unwrap();

        constraints_accumulator
            .process_outputs(&chain_config, block_height, &outputs)
            .unwrap();
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
                .staking_pool_spend_maturity_block_count(BlockCount::new(
                    required_spend_share_maturity,
                ))
                .build(),
        },
    )];
    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
        .consensus_upgrades(net_upgrades)
        .build();
    let block_height = BlockHeight::new(1);

    let pool_id = PoolId::new(H256::zero());
    let staked_atoms = rng.gen_range(100..1000);
    let stake_pool_data = create_stake_pool_data(&mut rng, staked_atoms);

    let delegation_id = DelegationId::new(H256::zero());
    let delegated_atoms = rng.gen_range(1..1000);

    let transferred_atoms = rng.gen_range(100..1000);

    let pledge_getter = |_| Ok(Some(Amount::from_atoms(staked_atoms)));
    let delegation_balance_getter = |_| Ok(Some(Amount::from_atoms(delegated_atoms)));
    let issuance_token_id_getter = |_| unreachable!();

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
            AccountSpending::DelegationBalance(delegation_id, Amount::from_atoms(delegated_atoms)),
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
                required_decommission_maturity + required_spend_share_maturity - 1,
            ),
        ),
        TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(transferred_atoms)),
            Destination::AnyoneCanSpend,
        ),
    ];

    let mut constraints_accumulator = constraints_accumulator::ConstrainedValueAccumulator::new();
    let result = constraints_accumulator
        .process_outputs(&chain_config, block_height, &outputs)
        .unwrap_err();
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
                required_decommission_maturity + required_spend_share_maturity,
            ),
        ),
        TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(transferred_atoms)),
            Destination::AnyoneCanSpend,
        ),
    ];

    let mut constraints_accumulator = constraints_accumulator::ConstrainedValueAccumulator::new();

    constraints_accumulator
        .process_inputs(
            &chain_config,
            block_height,
            pledge_getter,
            delegation_balance_getter,
            issuance_token_id_getter,
            &inputs,
            &inputs_utxos,
        )
        .unwrap();

    constraints_accumulator
        .process_outputs(&chain_config, block_height, &outputs)
        .unwrap();

    assert_eq!(
        constraints_accumulator
            .consume()
            .calculate_fee(&chain_config, BlockHeight::new(1))
            .unwrap(),
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
    let block_height = BlockHeight::new(1);

    let delegation_id = DelegationId::new(H256::zero());
    let delegation_balance = Amount::from_atoms(rng.gen_range(100..1000));
    let overspent_amount = (delegation_balance + Amount::from_atoms(1)).unwrap();

    let pledge_getter = |_| Ok(None);
    let delegation_balance_getter = |_| Ok(Some(delegation_balance));
    let issuance_token_id_getter = |_| unreachable!();

    // it's an error to spend more the balance
    let inputs = vec![TxInput::from_account(
        AccountNonce::new(0),
        AccountSpending::DelegationBalance(delegation_id, overspent_amount),
    )];
    let inputs_utxos = vec![None];

    {
        let mut constraints_accumulator =
            constraints_accumulator::ConstrainedValueAccumulator::new();
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

    // overspend in output
    let inputs = vec![TxInput::from_account(
        AccountNonce::new(0),
        AccountSpending::DelegationBalance(delegation_id, delegation_balance),
    )];
    let outputs = vec![TxOutput::LockThenTransfer(
        OutputValue::Coin(overspent_amount),
        Destination::AnyoneCanSpend,
        OutputTimeLock::ForBlockCount(
            chain_config
                .staking_pool_spend_maturity_block_count(BlockHeight::new(1))
                .to_int(),
        ),
    )];

    {
        let mut constraints_accumulator =
            constraints_accumulator::ConstrainedValueAccumulator::new();
        constraints_accumulator
            .process_inputs(
                &chain_config,
                block_height,
                pledge_getter,
                delegation_balance_getter,
                issuance_token_id_getter,
                &inputs,
                &inputs_utxos,
            )
            .unwrap();

        let result = constraints_accumulator.process_outputs(&chain_config, block_height, &outputs);
        assert_eq!(
            result.unwrap_err(),
            IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin)
        );
    }

    // valid case
    let inputs = vec![TxInput::from_account(
        AccountNonce::new(0),
        AccountSpending::DelegationBalance(delegation_id, delegation_balance),
    )];
    let outputs = vec![TxOutput::LockThenTransfer(
        OutputValue::Coin(delegation_balance),
        Destination::AnyoneCanSpend,
        OutputTimeLock::ForBlockCount(
            chain_config
                .staking_pool_spend_maturity_block_count(BlockHeight::new(1))
                .to_int(),
        ),
    )];

    {
        let mut constraints_accumulator =
            constraints_accumulator::ConstrainedValueAccumulator::new();
        constraints_accumulator
            .process_inputs(
                &chain_config,
                block_height,
                pledge_getter,
                delegation_balance_getter,
                issuance_token_id_getter,
                &inputs,
                &inputs_utxos,
            )
            .unwrap();

        constraints_accumulator
            .process_outputs(&chain_config, block_height, &outputs)
            .unwrap();
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn timelock_constraints_on_decommission_in_tx(#[case] seed: Seed) {
    let source_inputs = [lock_then_transfer(), transfer()];
    let source_outputs = [lock_then_transfer(), transfer(), burn(), delegate_staking()];

    let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
        .consensus_upgrades(NetUpgrades::regtest_with_pos())
        .build();
    let required_maturity_distance =
        chain_config.staking_pool_spend_maturity_block_count(BlockHeight::new(1));

    let mut rng = make_seedable_rng(seed);
    let number_of_inputs = rng.gen_range(0..10);
    let number_of_outputs = rng.gen_range(0..10);

    let pool_id = PoolId::new(H256::zero());
    let staked_atoms = rng.gen_range(100..1000);
    let stake_pool_data = create_stake_pool_data(&mut rng, staked_atoms);

    let pos_store = pos_accounting::InMemoryPoSAccounting::from_values(
        BTreeMap::from([(pool_id, stake_pool_data.clone().into())]),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    let pos_db = pos_accounting::PoSAccountingDB::new(&pos_store);

    let decommission_pool_utxo = if rng.gen::<bool>() {
        TxOutput::CreateStakePool(pool_id, Box::new(stake_pool_data))
    } else {
        produce_block()
    };

    let transferred_atoms = rng.gen_range(0..1000);

    let input_utxos = {
        let mut outputs = random_input_utxos(
            &mut rng,
            transferred_atoms,
            0..(required_maturity_distance.to_int() + 100),
        )
        .into_iter()
        .chain(std::iter::once(decommission_pool_utxo.clone()))
        .collect::<Vec<_>>();
        outputs.shuffle(&mut rng);
        outputs
    };

    // try to unlock random value
    {
        let random_additional_value = rng.gen_range(1..100);
        let timelocked_outputs = split_value(&mut rng, staked_atoms - random_additional_value)
            .iter()
            .map(|atoms| {
                let random_additional_value = rng.gen_range(0..10u64);
                TxOutput::LockThenTransfer(
                    OutputValue::Coin(Amount::from_atoms(*atoms)),
                    Destination::AnyoneCanSpend,
                    OutputTimeLock::ForBlockCount(
                        required_maturity_distance.to_int() + random_additional_value,
                    ),
                )
            })
            .collect::<Vec<_>>();

        let outputs = {
            let mut outputs = random_input_utxos(
                &mut rng,
                transferred_atoms + random_additional_value,
                0..required_maturity_distance.to_int(),
            )
            .into_iter()
            .chain(timelocked_outputs.into_iter())
            .collect::<Vec<_>>();
            outputs.shuffle(&mut rng);
            outputs
        };

        let (utxo_db, tx) = prepare_utxos_and_tx(&mut rng, input_utxos, outputs);

        let issuance_token_id_getter = |_| unreachable!();

        let err = check_tx_inputs_outputs_policy(
            &tx,
            &chain_config,
            BlockHeight::new(1),
            &pos_db,
            &utxo_db,
            issuance_token_id_getter,
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConnectTransactionError::IOPolicyError(
                IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin),
                tx.get_id().into()
            )
        );
    }

    // valid case
    {
        let input_utxos =
            get_random_outputs_combination(&mut rng, &source_inputs, number_of_inputs)
                .into_iter()
                .chain(std::iter::once(decommission_pool_utxo))
                .collect();

        let timelocked_outputs = split_value(&mut rng, staked_atoms)
            .iter()
            .map(|atoms| {
                let random_additional_distance = rng.gen_range(0..10);
                TxOutput::LockThenTransfer(
                    OutputValue::Coin(Amount::from_atoms(*atoms)),
                    Destination::AnyoneCanSpend,
                    OutputTimeLock::ForBlockCount(
                        required_maturity_distance.to_int() + random_additional_distance,
                    ),
                )
            })
            .collect::<Vec<_>>();

        let outputs = {
            let mut outputs =
                get_random_outputs_combination(&mut rng, &source_outputs, number_of_outputs)
                    .into_iter()
                    .chain(timelocked_outputs.into_iter())
                    .collect::<Vec<_>>();
            outputs.shuffle(&mut rng);
            outputs
        };

        let (utxo_db, tx) = prepare_utxos_and_tx(&mut rng, input_utxos, outputs);

        let issuance_token_id_getter = |_| unreachable!();

        check_tx_inputs_outputs_policy(
            &tx,
            &chain_config,
            BlockHeight::new(1),
            &pos_db,
            &utxo_db,
            issuance_token_id_getter,
        )
        .unwrap();
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn timelock_constraints_on_spend_share_in_tx(#[case] seed: Seed) {
    let source_outputs = [lock_then_transfer(), transfer(), burn(), delegate_staking()];

    let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
        .consensus_upgrades(NetUpgrades::regtest_with_pos())
        .build();
    let required_maturity_distance = chain_config
        .staking_pool_spend_maturity_block_count(BlockHeight::new(1))
        .to_int();

    let mut rng = make_seedable_rng(seed);
    let number_of_outputs = rng.gen_range(0..10);

    let delegation_id = DelegationId::new(H256::zero());
    let delegated_atoms = rng.gen_range(1..1000);
    let atoms_to_spend = rng.gen_range(1..=delegated_atoms);

    let pos_store = pos_accounting::InMemoryPoSAccounting::from_values(
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::from([(delegation_id, Amount::from_atoms(delegated_atoms))]),
        BTreeMap::new(),
    );
    let pos_db = pos_accounting::PoSAccountingDB::new(&pos_store);
    let utxo_db = UtxosDBInMemoryImpl::new(Id::<GenBlock>::new(H256::zero()), BTreeMap::new());

    // make timelock outputs but total atoms that locked is less than required
    {
        let random_additional_value = rng.gen_range(1..=atoms_to_spend);
        let timelocked_outputs = split_value(&mut rng, atoms_to_spend - random_additional_value)
            .iter()
            .map(|atoms| {
                let random_additional_distance = rng.gen_range(0..10);
                TxOutput::LockThenTransfer(
                    OutputValue::Coin(Amount::from_atoms(*atoms)),
                    Destination::AnyoneCanSpend,
                    OutputTimeLock::ForBlockCount(
                        required_maturity_distance + random_additional_distance,
                    ),
                )
            })
            .collect::<Vec<_>>();

        let outputs = {
            let mut outputs =
                random_input_utxos(&mut rng, delegated_atoms, 0..required_maturity_distance)
                    .into_iter()
                    .chain(timelocked_outputs.into_iter())
                    .collect::<Vec<_>>();
            outputs.shuffle(&mut rng);
            outputs
        };

        let tx = Transaction::new(
            0,
            vec![TxInput::from_account(
                AccountNonce::new(0),
                AccountSpending::DelegationBalance(
                    delegation_id,
                    Amount::from_atoms(atoms_to_spend),
                ),
            )],
            outputs,
        )
        .unwrap();

        let issuance_token_id_getter = |_| unreachable!();

        let res = check_tx_inputs_outputs_policy(
            &tx,
            &chain_config,
            BlockHeight::new(1),
            &pos_db,
            &utxo_db,
            issuance_token_id_getter,
        )
        .unwrap_err();
        assert_eq!(
            res,
            ConnectTransactionError::IOPolicyError(
                IOPolicyError::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin),
                tx.get_id().into()
            )
        )
    }

    // valid case
    {
        let timelocked_outputs = split_value(&mut rng, atoms_to_spend)
            .iter()
            .map(|atoms| {
                let random_additional_distance = rng.gen_range(0..10);
                TxOutput::LockThenTransfer(
                    OutputValue::Coin(Amount::from_atoms(*atoms)),
                    Destination::AnyoneCanSpend,
                    OutputTimeLock::ForBlockCount(
                        required_maturity_distance + random_additional_distance,
                    ),
                )
            })
            .collect::<Vec<_>>();

        let outputs = {
            let mut outputs =
                get_random_outputs_combination(&mut rng, &source_outputs, number_of_outputs)
                    .into_iter()
                    .chain(timelocked_outputs.into_iter())
                    .collect::<Vec<_>>();
            outputs.shuffle(&mut rng);
            outputs
        };

        let tx = Transaction::new(
            0,
            vec![TxInput::from_account(
                AccountNonce::new(0),
                AccountSpending::DelegationBalance(
                    delegation_id,
                    Amount::from_atoms(atoms_to_spend),
                ),
            )],
            outputs,
        )
        .unwrap();

        let issuance_token_id_getter = |_| unreachable!();

        check_tx_inputs_outputs_policy(
            &tx,
            &chain_config,
            BlockHeight::new(1),
            &pos_db,
            &utxo_db,
            issuance_token_id_getter,
        )
        .unwrap();
    }
}
