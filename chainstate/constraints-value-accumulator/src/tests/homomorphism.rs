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

use common::{
    chain::{
        config::ChainType, output_value::OutputValue, stakelock::StakePoolData,
        timelock::OutputTimeLock, AccountNonce, AccountSpending, DelegationId, Destination,
        NetUpgrades, OutPointSourceId, PoolId, Transaction, TxInput, TxOutput,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, Fee, Id, H256},
};
use crypto::vrf::{VRFKeyKind, VRFPrivateKey};
use randomness::{CryptoRng, Rng};
use rstest::rstest;
use test_utils::{
    random::{make_seedable_rng, Seed},
    split_value,
};

use crate::ConstrainedValueAccumulator;

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

// TODO: add more generic test with homomorphism prove

// The test proves that f(decommission + spend_share) = f(decommission) + f(spend_share),
// where f(x) is processing the tx with accumulator.
//
// Create 2 transactions. The first decommissions the pool and transfer some amount.
// The second one spends share from delegation and also transfers some amount.
// Actual amounts and the number of inputs/outputs used is random.
// Process both transactions using a single ConstrainedValueAccumulator.
// Then process them again but using separate accumulators per tx.
// The resulting objects must be equal.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn accumulators_homomorphism(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = common::chain::config::Builder::new(ChainType::Mainnet)
        .consensus_upgrades(NetUpgrades::regtest_with_pos())
        .build();
    let required_maturity_distance =
        chain_config.staking_pool_spend_maturity_block_count(BlockHeight::new(1));
    let block_height = BlockHeight::new(1);

    let pool_id = PoolId::new(H256::random_using(&mut rng));
    let delegation_id = DelegationId::new(H256::random_using(&mut rng));

    let transferred_atoms = rng.gen_range(0..1000);
    let staked_atoms = rng.gen_range(100..1000);
    let stake_pool_data = create_stake_pool_data(&mut rng, staked_atoms);
    let delegation_balance = Amount::from_atoms(rng.gen_range(100..1000));

    // total outputs is a part of total inputs because some random part goes as fees
    let decommission_output_atoms = rng.gen_range(1..staked_atoms);
    let share_to_spend_atoms = rng.gen_range(1..=delegation_balance.into_atoms());
    let spend_share_output = rng.gen_range(1..=share_to_spend_atoms);

    let expected_fee = Fee(Amount::from_atoms(
        transferred_atoms + transferred_atoms + staked_atoms + share_to_spend_atoms
            - transferred_atoms
            - transferred_atoms
            - decommission_output_atoms
            - spend_share_output,
    ));

    let pledge_getter = |_| Ok(Some(Amount::from_atoms(staked_atoms)));
    let delegation_balance_getter = |_| Ok(Some(delegation_balance));

    let (decommission_tx, decommission_tx_inputs_utxos) = {
        let decommission_pool_utxo = if rng.gen::<bool>() {
            TxOutput::CreateStakePool(pool_id, Box::new(stake_pool_data))
        } else {
            TxOutput::ProduceBlockFromStake(Destination::AnyoneCanSpend, pool_id)
        };

        let input_utxos: Vec<Option<TxOutput>> = split_value(&mut rng, transferred_atoms)
            .iter()
            .map(|atoms| {
                Some(TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(*atoms)),
                    Destination::AnyoneCanSpend,
                ))
            })
            .chain(std::iter::once(Some(decommission_pool_utxo)))
            .collect();
        let inputs: Vec<TxInput> = input_utxos
            .iter()
            .enumerate()
            .map(|(i, _)| {
                TxInput::from_utxo(
                    OutPointSourceId::Transaction(Id::new(H256::random_using(&mut rng))),
                    i as u32,
                )
            })
            .collect();

        let transfer_outputs = split_value(&mut rng, transferred_atoms).into_iter().map(|atoms| {
            TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(atoms)),
                Destination::AnyoneCanSpend,
            )
        });

        let locked_outputs =
            split_value(&mut rng, decommission_output_atoms).into_iter().map(|atoms| {
                let random_additional_distance = rng.gen_range(0..10);
                TxOutput::LockThenTransfer(
                    OutputValue::Coin(Amount::from_atoms(atoms)),
                    Destination::AnyoneCanSpend,
                    OutputTimeLock::ForBlockCount(
                        required_maturity_distance.to_int() + random_additional_distance,
                    ),
                )
            });

        let outputs = transfer_outputs.chain(locked_outputs).collect::<Vec<_>>();
        (Transaction::new(0, inputs, outputs).unwrap(), input_utxos)
    };

    let (spend_share_tx, spend_share_inputs_utxos) = {
        let input_utxos: Vec<Option<TxOutput>> = std::iter::once(None)
            .chain(
                split_value(&mut rng, transferred_atoms).iter().map(|atoms| {
                    Some(TxOutput::Transfer(
                        OutputValue::Coin(Amount::from_atoms(*atoms)),
                        Destination::AnyoneCanSpend,
                    ))
                }),
            )
            .collect();
        let inputs: Vec<TxInput> = input_utxos
            .iter()
            .enumerate()
            .map(|(i, _)| {
                if i == 0 {
                    TxInput::from_account(
                        AccountNonce::new(0),
                        AccountSpending::DelegationBalance(
                            delegation_id,
                            Amount::from_atoms(share_to_spend_atoms),
                        ),
                    )
                } else {
                    TxInput::from_utxo(
                        OutPointSourceId::Transaction(Id::new(H256::random_using(&mut rng))),
                        i as u32,
                    )
                }
            })
            .collect();

        let transfer_outputs = split_value(&mut rng, transferred_atoms).into_iter().map(|atoms| {
            TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(atoms)),
                Destination::AnyoneCanSpend,
            )
        });

        let locked_outputs = split_value(&mut rng, spend_share_output).into_iter().map(|atoms| {
            let random_additional_distance = rng.gen_range(0..10);
            TxOutput::LockThenTransfer(
                OutputValue::Coin(Amount::from_atoms(atoms)),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(
                    required_maturity_distance.to_int() + random_additional_distance,
                ),
            )
        });

        let outputs = transfer_outputs.chain(locked_outputs).collect::<Vec<_>>();
        (Transaction::new(0, inputs, outputs).unwrap(), input_utxos)
    };

    let consumed_accumulator_a = {
        let inputs = decommission_tx
            .inputs()
            .iter()
            .chain(spend_share_tx.inputs().iter())
            .cloned()
            .collect::<Vec<TxInput>>();
        let inputs_utxos = decommission_tx_inputs_utxos
            .iter()
            .chain(spend_share_inputs_utxos.iter())
            .cloned()
            .collect::<Vec<Option<TxOutput>>>();
        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            pledge_getter,
            delegation_balance_getter,
            &inputs,
            &inputs_utxos,
        )
        .unwrap();

        let outputs = decommission_tx
            .outputs()
            .iter()
            .chain(spend_share_tx.outputs())
            .cloned()
            .collect::<Vec<TxOutput>>();
        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        inputs_accumulator.satisfy_with(outputs_accumulator).unwrap()
    };

    let consumed_accumulator_b = {
        let decommission_inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            pledge_getter,
            delegation_balance_getter,
            decommission_tx.inputs(),
            &decommission_tx_inputs_utxos,
        )
        .unwrap();

        let decommission_outputs_accumulator = ConstrainedValueAccumulator::from_outputs(
            &chain_config,
            block_height,
            decommission_tx.outputs(),
        )
        .unwrap();

        let spend_share_inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            pledge_getter,
            delegation_balance_getter,
            spend_share_tx.inputs(),
            &spend_share_inputs_utxos,
        )
        .unwrap();

        let spend_share_outputs_accumulator = ConstrainedValueAccumulator::from_outputs(
            &chain_config,
            block_height,
            spend_share_tx.outputs(),
        )
        .unwrap();

        decommission_inputs_accumulator
            .satisfy_with(decommission_outputs_accumulator)
            .unwrap()
            .combine(
                spend_share_inputs_accumulator
                    .satisfy_with(spend_share_outputs_accumulator)
                    .unwrap(),
            )
            .unwrap()
    };

    assert_eq!(consumed_accumulator_a, consumed_accumulator_b);
    let fee_a = consumed_accumulator_a.map_into_block_fees(&chain_config, block_height).unwrap();
    let fee_b = consumed_accumulator_b.map_into_block_fees(&chain_config, block_height).unwrap();
    assert_eq!(fee_a, fee_b);
    assert_eq!(fee_a, expected_fee);
}
