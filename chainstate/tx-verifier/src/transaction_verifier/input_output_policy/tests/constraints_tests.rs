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
        timelock::OutputTimeLock, AccountNonce, AccountSpending, Destination, NetUpgrades, PoolId,
        TxOutput,
    },
    primitives::{per_thousand::PerThousand, Amount, CoinOrTokenId, H256},
};
use crypto::vrf::{VRFKeyKind, VRFPrivateKey};
use orders_accounting::{InMemoryOrdersAccounting, OrdersAccountingDB};
use randomness::{CryptoRng, Rng, SliceRandom};
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

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn timelock_constraints_on_decommission_in_tx(#[case] seed: Seed) {
    let source_inputs = [lock_then_transfer(), transfer(), htlc()];
    let source_outputs = [lock_then_transfer(), transfer(), htlc(), burn(), delegate_staking()];

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

    // FIXME: proper  impl
    let orders_store = InMemoryOrdersAccounting::new();
    let orders_db = OrdersAccountingDB::new(&orders_store);

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

        let err = check_tx_inputs_outputs_policy(
            &tx,
            &chain_config,
            BlockHeight::new(1),
            &orders_db,
            &pos_db,
            &utxo_db,
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConnectTransactionError::ConstrainedValueAccumulatorError(
                constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin),
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

        check_tx_inputs_outputs_policy(
            &tx,
            &chain_config,
            BlockHeight::new(1),
            &orders_db,
            &pos_db,
            &utxo_db,
        )
        .unwrap();
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn timelock_constraints_on_spend_share_in_tx(#[case] seed: Seed) {
    let source_outputs = [lock_then_transfer(), transfer(), htlc(), burn(), delegate_staking()];

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

    // FIXME: proper  impl
    let orders_store = InMemoryOrdersAccounting::new();
    let orders_db = OrdersAccountingDB::new(&orders_store);

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

        let res = check_tx_inputs_outputs_policy(
            &tx,
            &chain_config,
            BlockHeight::new(1),
            &orders_db,
            &pos_db,
            &utxo_db,
        )
        .unwrap_err();
        assert_eq!(
            res,
            ConnectTransactionError::ConstrainedValueAccumulatorError(
                constraints_value_accumulator::Error::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin),
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

        check_tx_inputs_outputs_policy(
            &tx,
            &chain_config,
            BlockHeight::new(1),
            &orders_db,
            &pos_db,
            &utxo_db,
        )
        .unwrap();
    }
}
