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
        config::ChainType, stakelock::StakePoolData, timelock::OutputTimeLock, tokens::OutputValue,
        AccountNonce, AccountSpending, Destination, NetUpgrades, PoolId, TxOutput,
    },
    primitives::{per_thousand::PerThousand, Amount, H256},
};
use crypto::{
    random::{Rng, SliceRandom},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

use super::*;

fn decompose_value(rng: &mut impl Rng, value: u128) -> Vec<u128> {
    let mut remaining = value;
    let mut result = Vec::new();

    while remaining > 0 {
        let fraction = rng.gen_range(1..=remaining);
        result.push(fraction);
        remaining -= fraction;
    }

    assert_eq!(value, result.iter().sum());

    result
}

fn create_stake_pool_data(atoms_to_stake: u128) -> StakePoolData {
    let (_, vrf_pub_key) = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel);
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
    let source_inputs = [lock_then_transfer(), transfer()];
    let source_outputs = [lock_then_transfer(), transfer(), burn(), delegate_staking()];

    let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
        .net_upgrades(NetUpgrades::regtest_with_pos())
        .build();
    let required_maturity_distance =
        chain_config.decommission_pool_maturity_distance(BlockHeight::new(1));

    let mut rng = make_seedable_rng(seed);
    let number_of_inputs = rng.gen_range(0..10);
    let number_of_outputs = rng.gen_range(0..10);

    let pool_id = PoolId::new(H256::zero());
    let staked_atoms = rng.gen_range(0..1000);
    let stake_pool_data = create_stake_pool_data(staked_atoms);

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

    let input_utxos = get_random_outputs_combination(&mut rng, &source_inputs, number_of_inputs)
        .into_iter()
        .chain(std::iter::once(decommission_pool_utxo.clone()))
        .collect::<Vec<_>>();

    // make timelock outputs but total atoms that locked is less then required
    {
        let random_additional_value = rng.gen_range(1..10u128);
        let timelocked_outputs = decompose_value(&mut rng, staked_atoms - random_additional_value)
            .iter()
            .map(|atoms| {
                let random_additional_value = rng.gen_range(0..10u64);
                TxOutput::LockThenTransfer(
                    OutputValue::Coin(Amount::from_atoms(*atoms)),
                    Destination::AnyoneCanSpend,
                    OutputTimeLock::ForBlockCount(
                        required_maturity_distance.into_int() as u64 + random_additional_value,
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

        let (utxo_db, tx) = prepare_utxos_and_tx(&mut rng, input_utxos.clone(), outputs);

        let err = check_tx_inputs_outputs_policy(
            &tx,
            &chain_config,
            BlockHeight::new(1),
            &pos_db,
            &utxo_db,
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConnectTransactionError::IOPolicyError(IOPolicyError::TimelockRequirementNotSatisfied(
                required_maturity_distance
            ))
        );
    }

    // make timelock outputs but distance is less then required
    {
        let timelocked_outputs = decompose_value(&mut rng, staked_atoms)
            .iter()
            .map(|atoms| {
                let random_additional_value = rng.gen_range(1..10u64);
                TxOutput::LockThenTransfer(
                    OutputValue::Coin(Amount::from_atoms(*atoms)),
                    Destination::AnyoneCanSpend,
                    OutputTimeLock::ForBlockCount(
                        required_maturity_distance.into_int() as u64 - random_additional_value,
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

        let err = check_tx_inputs_outputs_policy(
            &tx,
            &chain_config,
            BlockHeight::new(1),
            &pos_db,
            &utxo_db,
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConnectTransactionError::IOPolicyError(IOPolicyError::TimelockRequirementNotSatisfied(
                required_maturity_distance
            ))
        );
    }

    // valid case
    {
        let input_utxos =
            get_random_outputs_combination(&mut rng, &source_inputs, number_of_inputs)
                .into_iter()
                .chain(std::iter::once(decommission_pool_utxo))
                .collect();

        let timelocked_outputs = decompose_value(&mut rng, staked_atoms)
            .iter()
            .map(|atoms| {
                let random_additional_distance = rng.gen_range(0..10);
                TxOutput::LockThenTransfer(
                    OutputValue::Coin(Amount::from_atoms(*atoms)),
                    Destination::AnyoneCanSpend,
                    OutputTimeLock::ForBlockCount(
                        required_maturity_distance.into_int() as u64 + random_additional_distance,
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

        check_tx_inputs_outputs_policy(&tx, &chain_config, BlockHeight::new(1), &pos_db, &utxo_db)
            .unwrap();
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn timelock_constraints_on_spend_share_in_tx(#[case] seed: Seed) {
    let source_outputs = [lock_then_transfer(), transfer(), burn(), delegate_staking()];

    let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
        .net_upgrades(NetUpgrades::regtest_with_pos())
        .build();
    let required_maturity_distance =
        chain_config.spend_share_maturity_distance(BlockHeight::new(1));

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

    // make timelock outputs but total atoms that locked is less then required
    {
        let random_additional_value = rng.gen_range(1..10u128);
        let timelocked_outputs =
            decompose_value(&mut rng, atoms_to_spend - random_additional_value)
                .iter()
                .map(|atoms| {
                    let random_additional_distance = rng.gen_range(0..10);
                    TxOutput::LockThenTransfer(
                        OutputValue::Coin(Amount::from_atoms(*atoms)),
                        Destination::AnyoneCanSpend,
                        OutputTimeLock::ForBlockCount(
                            required_maturity_distance.into_int() as u64
                                + random_additional_distance,
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
                AccountSpending::Delegation(delegation_id, Amount::from_atoms(atoms_to_spend)),
            )],
            outputs,
        )
        .unwrap();

        let res = check_tx_inputs_outputs_policy(
            &tx,
            &chain_config,
            BlockHeight::new(1),
            &pos_db,
            &utxo_db,
        )
        .unwrap_err();
        assert_eq!(
            res,
            ConnectTransactionError::IOPolicyError(IOPolicyError::TimelockRequirementNotSatisfied(
                required_maturity_distance
            ))
        )
    }

    // make timelock outputs but total atoms that locked is less then required
    {
        let timelocked_outputs = decompose_value(&mut rng, atoms_to_spend)
            .iter()
            .map(|atoms| {
                let random_additional_distance = rng.gen_range(0..10);
                TxOutput::LockThenTransfer(
                    OutputValue::Coin(Amount::from_atoms(*atoms)),
                    Destination::AnyoneCanSpend,
                    OutputTimeLock::ForBlockCount(
                        required_maturity_distance.into_int() as u64 - random_additional_distance,
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
                AccountSpending::Delegation(delegation_id, Amount::from_atoms(atoms_to_spend)),
            )],
            outputs,
        )
        .unwrap();

        let res = check_tx_inputs_outputs_policy(
            &tx,
            &chain_config,
            BlockHeight::new(1),
            &pos_db,
            &utxo_db,
        )
        .unwrap_err();
        assert_eq!(
            res,
            ConnectTransactionError::IOPolicyError(IOPolicyError::TimelockRequirementNotSatisfied(
                required_maturity_distance
            ))
        )
    }

    // valid case
    {
        let timelocked_outputs = decompose_value(&mut rng, atoms_to_spend)
            .iter()
            .map(|atoms| {
                let random_additional_distance = rng.gen_range(0..10);
                TxOutput::LockThenTransfer(
                    OutputValue::Coin(Amount::from_atoms(*atoms)),
                    Destination::AnyoneCanSpend,
                    OutputTimeLock::ForBlockCount(
                        required_maturity_distance.into_int() as u64 + random_additional_distance,
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
                AccountSpending::Delegation(delegation_id, Amount::from_atoms(atoms_to_spend)),
            )],
            outputs,
        )
        .unwrap();

        check_tx_inputs_outputs_policy(&tx, &chain_config, BlockHeight::new(1), &pos_db, &utxo_db)
            .unwrap();
    }
}
