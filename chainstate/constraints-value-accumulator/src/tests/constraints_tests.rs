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
        config::ChainType,
        htlc::{HashedTimelockContract, HtlcSecret},
        output_value::OutputValue,
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::{NftIssuance, TokenId, TokenIssuance},
        AccountCommand, AccountNonce, AccountSpending, ConsensusUpgrade, DelegationId, Destination,
        NetUpgrades, OutPointSourceId, PoSChainConfigBuilder, PoolId, TxInput, TxOutput,
        UtxoOutPoint,
    },
    primitives::{
        per_thousand::PerThousand, Amount, BlockCount, BlockHeight, CoinOrTokenId, Fee, Id, H256,
    },
};
use crypto::vrf::{VRFKeyKind, VRFPrivateKey};
use orders_accounting::{InMemoryOrdersAccounting, OrdersAccountingDB};
use pos_accounting::{DelegationData, InMemoryPoSAccounting, PoSAccountingDB, PoolData};
use randomness::{CryptoRng, Rng};
use rstest::rstest;
use test_utils::{
    random::{make_seedable_rng, Seed},
    token_utils::random_nft_issuance,
};

use crate::{ConstrainedValueAccumulator, Error};

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

    let pos_store = InMemoryPoSAccounting::from_values(
        BTreeMap::from_iter([(pool_id, PoolData::from(stake_pool_data.clone()))]),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    let pos_db = PoSAccountingDB::new(&pos_store);

    let orders_store = InMemoryOrdersAccounting::new();
    let orders_db = OrdersAccountingDB::new(&orders_store);

    let tokens_store = tokens_accounting::InMemoryTokensAccounting::new();
    let tokens_db = tokens_accounting::TokensAccountingDB::new(&tokens_store);

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

    let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
        &chain_config,
        block_height,
        &orders_db,
        &pos_db,
        &tokens_db,
        &inputs,
        &input_utxos,
    )
    .unwrap();

    let outputs_accumulator =
        ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs).unwrap();

    let accumulated_fee = inputs_accumulator
        .satisfy_with(outputs_accumulator)
        .unwrap()
        .map_into_block_fees(&chain_config, block_height)
        .unwrap();

    assert_eq!(accumulated_fee, Fee(Amount::from_atoms(fee_atoms)));
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
    let delegation_data =
        DelegationData::new(PoolId::new(H256::zero()), Destination::AnyoneCanSpend);
    let delegated_atoms = rng.gen_range(100..1000);
    let fee_atoms = rng.gen_range(1..100);

    let pos_store = InMemoryPoSAccounting::from_values(
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::from_iter([(delegation_id, Amount::from_atoms(delegated_atoms))]),
        BTreeMap::from([(delegation_id, delegation_data)]),
    );
    let pos_db = PoSAccountingDB::new(&pos_store);

    let orders_store = InMemoryOrdersAccounting::new();
    let orders_db = OrdersAccountingDB::new(&orders_store);

    let tokens_store = tokens_accounting::InMemoryTokensAccounting::new();
    let tokens_db = tokens_accounting::TokensAccountingDB::new(&tokens_store);

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

    let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
        &chain_config,
        block_height,
        &orders_db,
        &pos_db,
        &tokens_db,
        &inputs,
        &inputs_utxos,
    )
    .unwrap();

    let outputs_accumulator =
        ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs).unwrap();

    let accumulated_fee = inputs_accumulator
        .satisfy_with(outputs_accumulator)
        .unwrap()
        .map_into_block_fees(&chain_config, block_height)
        .unwrap();

    assert_eq!(accumulated_fee, Fee(Amount::from_atoms(fee_atoms)));
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

    let pos_store = InMemoryPoSAccounting::from_values(
        BTreeMap::from_iter([(pool_id, PoolData::from(stake_pool_data.clone()))]),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    let pos_db = PoSAccountingDB::new(&pos_store);

    let orders_store = InMemoryOrdersAccounting::new();
    let orders_db = OrdersAccountingDB::new(&orders_store);

    let tokens_store = tokens_accounting::InMemoryTokensAccounting::new();
    let tokens_db = tokens_accounting::TokensAccountingDB::new(&tokens_store);

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
        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &tokens_db,
            &inputs,
            &inputs_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        let result = inputs_accumulator.satisfy_with(outputs_accumulator);
        assert_eq!(
            result.unwrap_err(),
            Error::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin)
        );
    }

    // it's not an error if output does not include staked coins
    let outputs = vec![TxOutput::Transfer(
        OutputValue::Coin(less_than_staked_amount),
        Destination::AnyoneCanSpend,
    )];

    {
        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &tokens_db,
            &inputs,
            &inputs_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        inputs_accumulator.satisfy_with(outputs_accumulator).unwrap();
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

    let pos_store = InMemoryPoSAccounting::from_values(
        BTreeMap::from_iter([(pool_id, PoolData::from(stake_pool_data.clone()))]),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    let pos_db = PoSAccountingDB::new(&pos_store);

    let orders_store = InMemoryOrdersAccounting::new();
    let orders_db = OrdersAccountingDB::new(&orders_store);

    let tokens_store = tokens_accounting::InMemoryTokensAccounting::new();
    let tokens_db = tokens_accounting::TokensAccountingDB::new(&tokens_store);

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

    let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
        &chain_config,
        block_height,
        &orders_db,
        &pos_db,
        &tokens_db,
        &inputs,
        &inputs_utxos,
    )
    .unwrap();

    let outputs_accumulator =
        ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs).unwrap();

    let result = inputs_accumulator.satisfy_with(outputs_accumulator);

    assert_eq!(
        result.unwrap_err(),
        Error::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin)
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
        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &tokens_db,
            &inputs,
            &inputs_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        inputs_accumulator.satisfy_with(outputs_accumulator).unwrap();
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

    let required_maturity = 200;
    let upgrades = vec![(
        BlockHeight::new(0),
        ConsensusUpgrade::PoS {
            initial_difficulty: None,
            config: PoSChainConfigBuilder::new_for_unit_test()
                .staking_pool_spend_maturity_block_count(BlockCount::new(required_maturity))
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
    let delegation_data =
        DelegationData::new(PoolId::new(H256::zero()), Destination::AnyoneCanSpend);
    let delegated_atoms = rng.gen_range(1..1000);

    let transferred_atoms = rng.gen_range(100..1000);

    let pos_store = InMemoryPoSAccounting::from_values(
        BTreeMap::from_iter([(pool_id, PoolData::from(stake_pool_data.clone()))]),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::from_iter([(delegation_id, Amount::from_atoms(delegated_atoms))]),
        BTreeMap::from([(delegation_id, delegation_data)]),
    );
    let pos_db = PoSAccountingDB::new(&pos_store);

    let orders_store = InMemoryOrdersAccounting::new();
    let orders_db = OrdersAccountingDB::new(&orders_store);

    let tokens_store = tokens_accounting::InMemoryTokensAccounting::new();
    let tokens_db = tokens_accounting::TokensAccountingDB::new(&tokens_store);

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
            OutputTimeLock::ForBlockCount(required_maturity - 1),
        ),
        TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(transferred_atoms)),
            Destination::AnyoneCanSpend,
        ),
    ];

    let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
        &chain_config,
        block_height,
        &orders_db,
        &pos_db,
        &tokens_db,
        &inputs,
        &inputs_utxos,
    )
    .unwrap();

    let outputs_accumulator =
        ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs).unwrap();

    let result = inputs_accumulator.satisfy_with(outputs_accumulator);
    assert_eq!(
        result.unwrap_err(),
        Error::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin)
    );

    // valid case
    let outputs = vec![
        TxOutput::LockThenTransfer(
            OutputValue::Coin(Amount::from_atoms(staked_atoms + delegated_atoms)),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(required_maturity),
        ),
        TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(transferred_atoms)),
            Destination::AnyoneCanSpend,
        ),
    ];

    let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
        &chain_config,
        block_height,
        &orders_db,
        &pos_db,
        &tokens_db,
        &inputs,
        &inputs_utxos,
    )
    .unwrap();

    let outputs_accumulator =
        ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs).unwrap();

    let accumulated_fee = inputs_accumulator
        .satisfy_with(outputs_accumulator)
        .unwrap()
        .map_into_block_fees(&chain_config, BlockHeight::new(1))
        .unwrap();

    assert_eq!(accumulated_fee, Fee(Amount::ZERO));
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
    let delegation_data =
        DelegationData::new(PoolId::new(H256::zero()), Destination::AnyoneCanSpend);
    let delegation_balance = Amount::from_atoms(rng.gen_range(100..1000));
    let overspent_amount = (delegation_balance + Amount::from_atoms(1)).unwrap();

    let pos_store = InMemoryPoSAccounting::from_values(
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::from_iter([(delegation_id, delegation_balance)]),
        BTreeMap::from([(delegation_id, delegation_data)]),
    );
    let pos_db = PoSAccountingDB::new(&pos_store);

    let orders_store = InMemoryOrdersAccounting::new();
    let orders_db = OrdersAccountingDB::new(&orders_store);

    let tokens_store = tokens_accounting::InMemoryTokensAccounting::new();
    let tokens_db = tokens_accounting::TokensAccountingDB::new(&tokens_store);

    // it's an error to spend more the balance
    let inputs = vec![TxInput::from_account(
        AccountNonce::new(0),
        AccountSpending::DelegationBalance(delegation_id, overspent_amount),
    )];
    let inputs_utxos = vec![None];

    {
        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &tokens_db,
            &inputs,
            &inputs_utxos,
        );

        assert_eq!(
            inputs_accumulator.unwrap_err(),
            Error::PoSAccountingError(pos_accounting::Error::AccountingError(
                accounting::Error::ArithmeticErrorSumToUnsignedFailed
            ))
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
        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &tokens_db,
            &inputs,
            &inputs_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        let result = inputs_accumulator.satisfy_with(outputs_accumulator);
        assert_eq!(
            result.unwrap_err(),
            Error::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin)
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
        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &tokens_db,
            &inputs,
            &inputs_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        inputs_accumulator.satisfy_with(outputs_accumulator).unwrap();
    }
}

// Check that token issuance fee is not accounted in accumulated fee and is burned rather then goes to staker.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn calculate_fee_for_token_issuance(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
        .consensus_upgrades(NetUpgrades::regtest_with_pos())
        .build();
    let block_height = BlockHeight::new(1);
    let token_issuance_fee = chain_config.fungible_token_issuance_fee();

    let pos_store = InMemoryPoSAccounting::new();
    let pos_db = PoSAccountingDB::new(&pos_store);

    let orders_store = InMemoryOrdersAccounting::new();
    let orders_db = OrdersAccountingDB::new(&orders_store);

    let tokens_store = tokens_accounting::InMemoryTokensAccounting::new();
    let tokens_db = tokens_accounting::TokensAccountingDB::new(&tokens_store);

    let inputs = vec![TxInput::Utxo(UtxoOutPoint::new(
        OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
        0,
    ))];
    let input_utxos = vec![Some(TxOutput::Transfer(
        OutputValue::Coin(token_issuance_fee),
        Destination::AnyoneCanSpend,
    ))];

    let outputs = vec![TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(
        test_utils::token_utils::random_token_issuance_v1(
            &chain_config,
            Destination::AnyoneCanSpend,
            &mut rng,
        ),
    )))];

    let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
        &chain_config,
        block_height,
        &orders_db,
        &pos_db,
        &tokens_db,
        &inputs,
        &input_utxos,
    )
    .unwrap();

    let outputs_accumulator =
        ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs).unwrap();

    let accumulated_fee = inputs_accumulator
        .satisfy_with(outputs_accumulator)
        .unwrap()
        .map_into_block_fees(&chain_config, block_height)
        .unwrap();

    assert_eq!(accumulated_fee, Fee(Amount::ZERO));
}

// Check that token supply change fee is not accounted in accumulated fee and is burned rather then goes to staker.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn calculate_token_supply_change_fee(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
        .consensus_upgrades(NetUpgrades::regtest_with_pos())
        .build();
    let block_height = BlockHeight::new(1);
    let supply_change_fee = chain_config.token_supply_change_fee(BlockHeight::zero());

    let pos_store = InMemoryPoSAccounting::new();
    let pos_db = PoSAccountingDB::new(&pos_store);

    let orders_store = InMemoryOrdersAccounting::new();
    let orders_db = OrdersAccountingDB::new(&orders_store);

    let token_data = tokens_accounting::TokenData::FungibleToken(
        TokenIssuance::V1(test_utils::token_utils::random_token_issuance_v1(
            &chain_config,
            Destination::AnyoneCanSpend,
            &mut rng,
        ))
        .into(),
    );
    let token_id = TokenId::random_using(&mut rng);
    let tokens_store = tokens_accounting::InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data)]),
        BTreeMap::new(),
    );
    let tokens_db = tokens_accounting::TokensAccountingDB::new(&tokens_store);

    // Mint
    {
        let inputs = vec![
            TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::MintTokens(token_id, Amount::from_atoms(1)),
            ),
            TxInput::Utxo(UtxoOutPoint::new(
                OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
                0,
            )),
        ];
        let input_utxos = vec![
            None,
            Some(TxOutput::Transfer(
                OutputValue::Coin(supply_change_fee),
                Destination::AnyoneCanSpend,
            )),
        ];

        let outputs =
            vec![TxOutput::Transfer(OutputValue::Coin(Amount::ZERO), Destination::AnyoneCanSpend)];

        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &tokens_db,
            &inputs,
            &input_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        let accumulated_fee = inputs_accumulator
            .satisfy_with(outputs_accumulator)
            .unwrap()
            .map_into_block_fees(&chain_config, block_height)
            .unwrap();

        assert_eq!(accumulated_fee, Fee(Amount::ZERO));
    }

    // Unmint
    {
        let inputs = vec![
            TxInput::AccountCommand(AccountNonce::new(0), AccountCommand::UnmintTokens(token_id)),
            TxInput::Utxo(UtxoOutPoint::new(
                OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
                0,
            )),
        ];
        let input_utxos = vec![
            None,
            Some(TxOutput::Transfer(
                OutputValue::Coin(supply_change_fee),
                Destination::AnyoneCanSpend,
            )),
        ];

        let outputs =
            vec![TxOutput::Transfer(OutputValue::Coin(Amount::ZERO), Destination::AnyoneCanSpend)];

        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &tokens_db,
            &inputs,
            &input_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        let accumulated_fee = inputs_accumulator
            .satisfy_with(outputs_accumulator)
            .unwrap()
            .map_into_block_fees(&chain_config, block_height)
            .unwrap();

        assert_eq!(accumulated_fee, Fee(Amount::ZERO));
    }

    // Lock supply
    {
        let inputs = vec![
            TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::LockTokenSupply(token_id),
            ),
            TxInput::Utxo(UtxoOutPoint::new(
                OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
                0,
            )),
        ];
        let input_utxos = vec![
            None,
            Some(TxOutput::Transfer(
                OutputValue::Coin(supply_change_fee),
                Destination::AnyoneCanSpend,
            )),
        ];

        let outputs =
            vec![TxOutput::Transfer(OutputValue::Coin(Amount::ZERO), Destination::AnyoneCanSpend)];

        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &tokens_db,
            &inputs,
            &input_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        let accumulated_fee = inputs_accumulator
            .satisfy_with(outputs_accumulator)
            .unwrap()
            .map_into_block_fees(&chain_config, block_height)
            .unwrap();

        assert_eq!(accumulated_fee, Fee(Amount::ZERO));
    }
}

// Check that token freeze fee is not accounted in accumulated fee and is burned rather then goes to staker.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn calculate_token_fee_freeze(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
        .consensus_upgrades(NetUpgrades::regtest_with_pos())
        .build();
    let block_height = BlockHeight::new(1);
    let supply_change_fee = chain_config.token_freeze_fee(BlockHeight::zero());

    let pos_store = InMemoryPoSAccounting::new();
    let pos_db = PoSAccountingDB::new(&pos_store);

    let orders_store = InMemoryOrdersAccounting::new();
    let orders_db = OrdersAccountingDB::new(&orders_store);

    let token_data = tokens_accounting::TokenData::FungibleToken(
        TokenIssuance::V1(test_utils::token_utils::random_token_issuance_v1(
            &chain_config,
            Destination::AnyoneCanSpend,
            &mut rng,
        ))
        .into(),
    );
    let token_id = TokenId::random_using(&mut rng);
    let tokens_store = tokens_accounting::InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data)]),
        BTreeMap::new(),
    );
    let tokens_db = tokens_accounting::TokensAccountingDB::new(&tokens_store);

    // Freeze
    {
        let inputs = vec![
            TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FreezeToken(
                    token_id,
                    common::chain::tokens::IsTokenUnfreezable::Yes,
                ),
            ),
            TxInput::Utxo(UtxoOutPoint::new(
                OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
                0,
            )),
        ];
        let input_utxos = vec![
            None,
            Some(TxOutput::Transfer(
                OutputValue::Coin(supply_change_fee),
                Destination::AnyoneCanSpend,
            )),
        ];

        let outputs =
            vec![TxOutput::Transfer(OutputValue::Coin(Amount::ZERO), Destination::AnyoneCanSpend)];

        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &tokens_db,
            &inputs,
            &input_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        let accumulated_fee = inputs_accumulator
            .satisfy_with(outputs_accumulator)
            .unwrap()
            .map_into_block_fees(&chain_config, block_height)
            .unwrap();

        assert_eq!(accumulated_fee, Fee(Amount::ZERO));
    }

    // Unfreeze
    {
        let inputs = vec![
            TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::UnfreezeToken(token_id),
            ),
            TxInput::Utxo(UtxoOutPoint::new(
                OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
                0,
            )),
        ];
        let input_utxos = vec![
            None,
            Some(TxOutput::Transfer(
                OutputValue::Coin(supply_change_fee),
                Destination::AnyoneCanSpend,
            )),
        ];

        let outputs =
            vec![TxOutput::Transfer(OutputValue::Coin(Amount::ZERO), Destination::AnyoneCanSpend)];

        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &tokens_db,
            &inputs,
            &input_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        let accumulated_fee = inputs_accumulator
            .satisfy_with(outputs_accumulator)
            .unwrap()
            .map_into_block_fees(&chain_config, block_height)
            .unwrap();

        assert_eq!(accumulated_fee, Fee(Amount::ZERO));
    }
}

// Check that token authority change fee is not accounted in accumulated fee and is burned rather then goes to staker.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn calculate_token_fee_change_authority(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
        .consensus_upgrades(NetUpgrades::regtest_with_pos())
        .build();
    let block_height = BlockHeight::new(1);
    let supply_change_fee = chain_config.token_change_authority_fee(BlockHeight::zero());

    let pos_store = InMemoryPoSAccounting::new();
    let pos_db = PoSAccountingDB::new(&pos_store);

    let orders_store = InMemoryOrdersAccounting::new();
    let orders_db = OrdersAccountingDB::new(&orders_store);

    let token_data = tokens_accounting::TokenData::FungibleToken(
        TokenIssuance::V1(test_utils::token_utils::random_token_issuance_v1(
            &chain_config,
            Destination::AnyoneCanSpend,
            &mut rng,
        ))
        .into(),
    );
    let token_id = TokenId::random_using(&mut rng);
    let tokens_store = tokens_accounting::InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data)]),
        BTreeMap::new(),
    );
    let tokens_db = tokens_accounting::TokensAccountingDB::new(&tokens_store);

    let inputs = vec![
        TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::ChangeTokenAuthority(token_id, Destination::AnyoneCanSpend),
        ),
        TxInput::Utxo(UtxoOutPoint::new(
            OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
            0,
        )),
    ];
    let input_utxos = vec![
        None,
        Some(TxOutput::Transfer(
            OutputValue::Coin(supply_change_fee),
            Destination::AnyoneCanSpend,
        )),
    ];

    let outputs =
        vec![TxOutput::Transfer(OutputValue::Coin(Amount::ZERO), Destination::AnyoneCanSpend)];

    let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
        &chain_config,
        block_height,
        &orders_db,
        &pos_db,
        &tokens_db,
        &inputs,
        &input_utxos,
    )
    .unwrap();

    let outputs_accumulator =
        ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs).unwrap();

    let accumulated_fee = inputs_accumulator
        .satisfy_with(outputs_accumulator)
        .unwrap()
        .map_into_block_fees(&chain_config, block_height)
        .unwrap();

    assert_eq!(accumulated_fee, Fee(Amount::ZERO));
}

// Check that data deposit fee is not accounted in accumulated fee and is burned rather then goes to staker.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn calculate_data_deposit_fee(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
        .consensus_upgrades(NetUpgrades::regtest_with_pos())
        .build();
    let block_height = BlockHeight::new(1);
    let data_deposit_fee = chain_config.data_deposit_fee(block_height);

    let pos_store = InMemoryPoSAccounting::new();
    let pos_db = PoSAccountingDB::new(&pos_store);

    let orders_store = InMemoryOrdersAccounting::new();
    let orders_db = OrdersAccountingDB::new(&orders_store);

    let tokens_store = tokens_accounting::InMemoryTokensAccounting::new();
    let tokens_db = tokens_accounting::TokensAccountingDB::new(&tokens_store);

    let inputs = vec![TxInput::Utxo(UtxoOutPoint::new(
        OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
        0,
    ))];
    let input_utxos = vec![Some(TxOutput::Transfer(
        OutputValue::Coin(data_deposit_fee),
        Destination::AnyoneCanSpend,
    ))];

    let outputs = vec![TxOutput::DataDeposit(Vec::new())];

    let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
        &chain_config,
        block_height,
        &orders_db,
        &pos_db,
        &tokens_db,
        &inputs,
        &input_utxos,
    )
    .unwrap();

    let outputs_accumulator =
        ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs).unwrap();

    let accumulated_fee = inputs_accumulator
        .satisfy_with(outputs_accumulator)
        .unwrap()
        .map_into_block_fees(&chain_config, block_height)
        .unwrap();

    assert_eq!(accumulated_fee, Fee(Amount::ZERO));
}

// Check that nft issuance fee is not accounted in accumulated fee and is burned rather then goes to staker.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn calculate_nft_issuance_fee(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
        .consensus_upgrades(NetUpgrades::regtest_with_pos())
        .build();
    let block_height = BlockHeight::new(1);
    let nft_issuance_fee = chain_config.nft_issuance_fee(BlockHeight::zero());

    let pos_store = InMemoryPoSAccounting::new();
    let pos_db = PoSAccountingDB::new(&pos_store);

    let orders_store = InMemoryOrdersAccounting::new();
    let orders_db = OrdersAccountingDB::new(&orders_store);

    let tokens_store = tokens_accounting::InMemoryTokensAccounting::new();
    let tokens_db = tokens_accounting::TokensAccountingDB::new(&tokens_store);

    let inputs = vec![TxInput::Utxo(UtxoOutPoint::new(
        OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
        0,
    ))];
    let input_utxos = vec![Some(TxOutput::Transfer(
        OutputValue::Coin(nft_issuance_fee),
        Destination::AnyoneCanSpend,
    ))];

    let issuance = random_nft_issuance(&chain_config, &mut rng);
    let outputs = vec![TxOutput::IssueNft(
        TokenId::zero(),
        Box::new(NftIssuance::V0(issuance)),
        Destination::AnyoneCanSpend,
    )];

    let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
        &chain_config,
        block_height,
        &orders_db,
        &pos_db,
        &tokens_db,
        &inputs,
        &input_utxos,
    )
    .unwrap();

    let outputs_accumulator =
        ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs).unwrap();

    let accumulated_fee = inputs_accumulator
        .satisfy_with(outputs_accumulator)
        .unwrap()
        .map_into_block_fees(&chain_config, block_height)
        .unwrap();

    assert_eq!(accumulated_fee, Fee(Amount::ZERO));
}

// Check that token metadata change fee is not accounted in accumulated fee and is burned rather then goes to staker.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn calculate_token_fee_change_metadata_uri(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
        .consensus_upgrades(NetUpgrades::regtest_with_pos())
        .build();
    let block_height = BlockHeight::new(1);
    let change_metadata_uri_fee = chain_config.token_change_metadata_uri_fee();

    let pos_store = InMemoryPoSAccounting::new();
    let pos_db = PoSAccountingDB::new(&pos_store);

    let orders_store = InMemoryOrdersAccounting::new();
    let orders_db = OrdersAccountingDB::new(&orders_store);

    let token_data = tokens_accounting::TokenData::FungibleToken(
        TokenIssuance::V1(test_utils::token_utils::random_token_issuance_v1(
            &chain_config,
            Destination::AnyoneCanSpend,
            &mut rng,
        ))
        .into(),
    );
    let token_id = TokenId::random_using(&mut rng);
    let tokens_store = tokens_accounting::InMemoryTokensAccounting::from_values(
        BTreeMap::from_iter([(token_id, token_data)]),
        BTreeMap::new(),
    );
    let tokens_db = tokens_accounting::TokensAccountingDB::new(&tokens_store);

    let inputs = vec![
        TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::ChangeTokenMetadataUri(token_id, Vec::new()),
        ),
        TxInput::Utxo(UtxoOutPoint::new(
            OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
            0,
        )),
    ];
    let input_utxos = vec![
        None,
        Some(TxOutput::Transfer(
            OutputValue::Coin(change_metadata_uri_fee),
            Destination::AnyoneCanSpend,
        )),
    ];

    let outputs =
        vec![TxOutput::Transfer(OutputValue::Coin(Amount::ZERO), Destination::AnyoneCanSpend)];

    let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
        &chain_config,
        block_height,
        &orders_db,
        &pos_db,
        &tokens_db,
        &inputs,
        &input_utxos,
    )
    .unwrap();

    let outputs_accumulator =
        ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs).unwrap();

    let accumulated_fee = inputs_accumulator
        .satisfy_with(outputs_accumulator)
        .unwrap()
        .map_into_block_fees(&chain_config, block_height)
        .unwrap();

    assert_eq!(accumulated_fee, Fee(Amount::ZERO));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn htlc_output(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
        .consensus_upgrades(NetUpgrades::regtest_with_pos())
        .build();
    let block_height = BlockHeight::new(1);
    let balance = Amount::from_atoms(rng.gen_range(1..1000));

    let pos_store = InMemoryPoSAccounting::new();
    let pos_db = PoSAccountingDB::new(&pos_store);

    let orders_store = InMemoryOrdersAccounting::new();
    let orders_db = OrdersAccountingDB::new(&orders_store);

    let tokens_store = tokens_accounting::InMemoryTokensAccounting::new();
    let tokens_db = tokens_accounting::TokensAccountingDB::new(&tokens_store);

    let inputs = vec![TxInput::Utxo(UtxoOutPoint::new(
        OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
        0,
    ))];
    let input_utxos = vec![Some(TxOutput::Transfer(
        OutputValue::Coin(balance),
        Destination::AnyoneCanSpend,
    ))];

    let secret = HtlcSecret::new_from_rng(&mut rng);
    let htlc = HashedTimelockContract {
        secret_hash: secret.hash(),
        spend_key: Destination::AnyoneCanSpend,
        refund_timelock: OutputTimeLock::ForSeconds(1),
        refund_key: Destination::AnyoneCanSpend,
    };

    // Try overspend with htlc output
    {
        let outputs = vec![TxOutput::Htlc(
            OutputValue::Coin((balance + Amount::from_atoms(1)).unwrap()),
            Box::new(htlc.clone()),
        )];

        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &tokens_db,
            &inputs,
            &input_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        let result = inputs_accumulator.satisfy_with(outputs_accumulator);

        assert_eq!(
            result.unwrap_err(),
            Error::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin)
        );
    }

    // Ok case
    let outputs = vec![TxOutput::Htlc(OutputValue::Coin(balance), Box::new(htlc))];

    let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
        &chain_config,
        block_height,
        &orders_db,
        &pos_db,
        &tokens_db,
        &inputs,
        &input_utxos,
    )
    .unwrap();

    let outputs_accumulator =
        ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs).unwrap();

    let accumulated_fee = inputs_accumulator
        .satisfy_with(outputs_accumulator)
        .unwrap()
        .map_into_block_fees(&chain_config, block_height)
        .unwrap();

    assert_eq!(accumulated_fee, Fee(Amount::ZERO));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn htlc_input(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
        .consensus_upgrades(NetUpgrades::regtest_with_pos())
        .build();
    let block_height = BlockHeight::new(1);
    let balance = Amount::from_atoms(rng.gen_range(1..1000));

    let pos_store = InMemoryPoSAccounting::new();
    let pos_db = PoSAccountingDB::new(&pos_store);

    let orders_store = InMemoryOrdersAccounting::new();
    let orders_db = OrdersAccountingDB::new(&orders_store);

    let tokens_store = tokens_accounting::InMemoryTokensAccounting::new();
    let tokens_db = tokens_accounting::TokensAccountingDB::new(&tokens_store);

    let inputs = vec![TxInput::Utxo(UtxoOutPoint::new(
        OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
        0,
    ))];

    let secret = HtlcSecret::new_from_rng(&mut rng);
    let htlc = HashedTimelockContract {
        secret_hash: secret.hash(),
        spend_key: Destination::AnyoneCanSpend,
        refund_timelock: OutputTimeLock::ForSeconds(1),
        refund_key: Destination::AnyoneCanSpend,
    };

    let input_utxos = vec![Some(TxOutput::Htlc(OutputValue::Coin(balance), Box::new(htlc)))];

    // Try overspend with htlc input
    {
        let outputs = vec![TxOutput::Transfer(
            OutputValue::Coin((balance + Amount::from_atoms(1)).unwrap()),
            Destination::AnyoneCanSpend,
        )];

        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &tokens_db,
            &inputs,
            &input_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        let result = inputs_accumulator.satisfy_with(outputs_accumulator);

        assert_eq!(
            result.unwrap_err(),
            Error::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin)
        );
    }

    // Ok case
    let outputs = vec![TxOutput::Transfer(OutputValue::Coin(balance), Destination::AnyoneCanSpend)];

    let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
        &chain_config,
        block_height,
        &orders_db,
        &pos_db,
        &tokens_db,
        &inputs,
        &input_utxos,
    )
    .unwrap();

    let outputs_accumulator =
        ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs).unwrap();

    let accumulated_fee = inputs_accumulator
        .satisfy_with(outputs_accumulator)
        .unwrap()
        .map_into_block_fees(&chain_config, block_height)
        .unwrap();

    assert_eq!(accumulated_fee, Fee(Amount::ZERO));
}
