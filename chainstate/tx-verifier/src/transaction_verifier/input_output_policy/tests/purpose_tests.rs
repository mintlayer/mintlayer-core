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

use rstest::rstest;

use common::{
    chain::{
        self, stakelock::StakePoolData, Destination, GenBlock, NetUpgrades, OutPointSourceId,
        StakerDestinationUpdateForbidden, TxInput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Id, H256},
};
use common_test_helpers::chainstate_upgrade_builder::ChainstateUpgradeBuilder;
use crypto::key::{KeyKind, PrivateKey};
use randomness::{Rng, SliceRandom};
use test_utils::{
    assert_matches,
    random::{make_seedable_rng, Seed},
};
use utxo::{Utxo, UtxosDBInMemoryImpl};

use super::{outputs_utils::*, purposes_check::*, *};

use crate::error::SpendStakeError;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tx_stake_multiple_pools(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let source_inputs = super::outputs_utils::valid_tx_inputs_utxos();
    let source_valid_outputs =
        [lock_then_transfer(), transfer(), htlc(), burn(), delegate_staking()];
    let source_invalid_outputs = [stake_pool()];

    let inputs = get_random_outputs_combination(&mut rng, &source_inputs, 1);

    let number_of_valid_outputs = rng.gen_range(0..10);
    let number_of_invalid_outputs = rng.gen_range(2..10);
    let outputs =
        get_random_outputs_combination(&mut rng, &source_valid_outputs, number_of_valid_outputs)
            .into_iter()
            .chain(
                get_random_outputs_combination(
                    &mut rng,
                    &source_invalid_outputs,
                    number_of_invalid_outputs,
                )
                .into_iter(),
            )
            .collect();

    let (utxo_db, tx) = prepare_utxos_and_tx(&mut rng, inputs, outputs);

    let inputs_utxos = collect_inputs_utxos(&utxo_db, tx.inputs()).unwrap();
    let result = check_tx_inputs_outputs_purposes(&tx, &inputs_utxos).unwrap_err();
    assert_eq!(result, IOPolicyError::MultiplePoolCreated);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tx_create_multiple_delegations(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let source_inputs = super::outputs_utils::valid_tx_inputs_utxos();
    let source_valid_outputs =
        [lock_then_transfer(), transfer(), htlc(), burn(), delegate_staking()];
    let source_invalid_outputs = [create_delegation()];

    let inputs = get_random_outputs_combination(&mut rng, &source_inputs, 1);

    let number_of_valid_outputs = rng.gen_range(0..10);
    let number_of_invalid_outputs = rng.gen_range(2..10);
    let outputs =
        get_random_outputs_combination(&mut rng, &source_valid_outputs, number_of_valid_outputs)
            .into_iter()
            .chain(
                get_random_outputs_combination(
                    &mut rng,
                    &source_invalid_outputs,
                    number_of_invalid_outputs,
                )
                .into_iter(),
            )
            .collect();

    let (utxo_db, tx) = prepare_utxos_and_tx(&mut rng, inputs, outputs);

    let inputs_utxos = collect_inputs_utxos(&utxo_db, tx.inputs()).unwrap();
    let result = check_tx_inputs_outputs_purposes(&tx, &inputs_utxos).unwrap_err();
    assert_eq!(result, IOPolicyError::MultipleDelegationCreated);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tx_many_to_many_valid(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let number_of_inputs = rng.gen_range(1..10);
    let number_of_outputs = rng.gen_range(1..10);

    let valid_inputs = valid_tx_inputs_utxos();
    // stake pool and create delegation are skipped to avoid dealing with uniqueness
    let valid_outputs = [
        lock_then_transfer(),
        transfer(),
        htlc(),
        burn(),
        delegate_staking(),
        issue_tokens(),
        issue_nft(),
        data_deposit(),
    ];

    let (utxo_db, tx) = prepare_utxos_and_tx_with_random_combinations(
        &mut rng,
        &valid_inputs,
        number_of_inputs,
        &valid_outputs,
        number_of_outputs,
        None,
    );
    let inputs_utxos = collect_inputs_utxos(&utxo_db, tx.inputs()).unwrap();
    check_tx_inputs_outputs_purposes(&tx, &inputs_utxos).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tx_many_to_many_valid_with_account_input(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let number_of_inputs = rng.gen_range(1..10);
    let number_of_outputs = rng.gen_range(1..10);

    let account_inputs = all_account_inputs();
    // stake pool and create delegation are skipped to avoid dealing with uniqueness
    let valid_outputs = [
        lock_then_transfer(),
        transfer(),
        burn(),
        delegate_staking(),
        issue_tokens(),
        issue_nft(),
        data_deposit(),
    ];

    let inputs_utxos = get_random_outputs_combination(
        &mut rng,
        &super::outputs_utils::valid_tx_inputs_utxos(),
        number_of_inputs,
    );

    let inputs = {
        let mut inputs = inputs_utxos
            .iter()
            .enumerate()
            .map(|(i, _)| {
                TxInput::from_utxo(
                    OutPointSourceId::Transaction(Id::new(H256::zero())),
                    i as u32,
                )
            })
            .chain(get_random_inputs_combination(&mut rng, &account_inputs, 1))
            .collect::<Vec<_>>();
        inputs.shuffle(&mut rng);
        inputs
    };

    let outputs = get_random_outputs_combination(&mut rng, &valid_outputs, number_of_outputs);

    let tx = Transaction::new(0, inputs, outputs).unwrap();

    check_tx_inputs_outputs_purposes(&tx, &inputs_utxos).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tx_many_to_many_invalid_inputs(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let number_of_inputs = rng.gen_range(1..10);
    let number_of_outputs = rng.gen_range(1..10);

    let valid_inputs = super::outputs_utils::valid_tx_inputs_utxos();
    let valid_outputs = super::outputs_utils::valid_tx_outputs();

    let invalid_inputs = invalid_tx_inputs_utxos();

    let input_utxos = {
        let mut outputs =
            get_random_outputs_combination(&mut rng, &invalid_inputs, number_of_inputs)
                .into_iter()
                .chain(get_random_outputs_combination(
                    &mut rng,
                    &valid_inputs,
                    number_of_inputs,
                ))
                .collect::<Vec<_>>();
        outputs.shuffle(&mut rng);
        outputs
    };

    let outputs = get_random_outputs_combination(&mut rng, &valid_outputs, number_of_outputs);
    let (utxo_db, tx) = prepare_utxos_and_tx(&mut rng, input_utxos, outputs);
    let inputs_utxos = collect_inputs_utxos(&utxo_db, tx.inputs()).unwrap();

    assert_eq!(
        check_tx_inputs_outputs_purposes(&tx, &inputs_utxos).unwrap_err(),
        IOPolicyError::InvalidInputTypeInTx,
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn produce_block_in_tx_output(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let number_of_inputs = rng.gen_range(1..10);
    let number_of_outputs = rng.gen_range(1..10);

    let valid_inputs = super::outputs_utils::valid_tx_inputs_utxos();
    let valid_outputs = super::outputs_utils::valid_tx_outputs();
    let invalid_outputs = [produce_block()];

    let input_utxos = get_random_outputs_combination(&mut rng, &valid_inputs, number_of_inputs);

    let outputs = {
        let mut outputs =
            get_random_outputs_combination(&mut rng, &invalid_outputs, number_of_outputs)
                .into_iter()
                .chain(get_random_outputs_combination(
                    &mut rng,
                    &valid_outputs,
                    number_of_outputs,
                ))
                .collect::<Vec<_>>();
        outputs.shuffle(&mut rng);
        outputs
    };

    let (utxo_db, tx) = prepare_utxos_and_tx(&mut rng, input_utxos, outputs);
    let inputs_utxos = collect_inputs_utxos(&utxo_db, tx.inputs()).unwrap();

    assert_eq!(
        check_tx_inputs_outputs_purposes(&tx, &inputs_utxos).unwrap_err(),
        IOPolicyError::ProduceBlockInTx,
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tx_create_pool_and_delegation_same_tx(#[case] seed: Seed) {
    let source_inputs = [transfer(), htlc(), lock_then_transfer()];
    let outputs = [stake_pool(), create_delegation()];

    let mut rng = make_seedable_rng(seed);
    let number_of_inputs = rng.gen_range(2..10);
    let input_utxos = get_random_outputs_combination(&mut rng, &source_inputs, number_of_inputs);

    let (utxo_db, tx) = prepare_utxos_and_tx(&mut rng, input_utxos, outputs.to_vec());
    let inputs_utxos = collect_inputs_utxos(&utxo_db, tx.inputs()).unwrap();
    assert_eq!(check_tx_inputs_outputs_purposes(&tx, &inputs_utxos), Ok(()));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reward_one_to_one(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = chain::config::Builder::test_chain().build();
    let all_outputs = super::outputs_utils::all_outputs();
    let input_utxo = get_random_outputs_combination(&mut rng, &all_outputs, 1)[0].clone();
    let output = get_random_outputs_combination(&mut rng, &all_outputs, 1)[0].clone();

    let outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(Id::new(H256::zero())), 0);
    let utxo_db = UtxosDBInMemoryImpl::new(
        Id::<GenBlock>::new(H256::zero()),
        BTreeMap::from_iter([(outpoint.clone(), Utxo::new_for_mempool(input_utxo.clone()))]),
    );

    let block = make_block(vec![outpoint.into()], vec![output.clone()]);
    let block_height = BlockHeight::new(rng.gen());

    let result = check_reward_inputs_outputs_purposes(
        &chain_config,
        &block.block_reward_transactable(),
        &utxo_db,
        block.get_id(),
        block_height,
    );

    if (is_stake_pool(&input_utxo) || is_produce_block(&input_utxo)) && is_produce_block(&output) {
        assert!(result.is_ok());
    } else {
        assert!(result.is_err());
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reward_one_to_none(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = chain::config::Builder::test_chain().build();
    let valid_kernels = [stake_pool(), produce_block()];

    let input = get_random_outputs_combination(&mut rng, &valid_kernels, 1)
        .into_iter()
        .next()
        .unwrap();
    let outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(Id::new(H256::zero())), 0);

    let best_block_id: Id<GenBlock> = Id::new(H256::random_using(&mut rng));
    let utxo_db = UtxosDBInMemoryImpl::new(
        best_block_id,
        BTreeMap::from_iter([(outpoint.clone(), Utxo::new_for_mempool(input))]),
    );

    let block = make_block(vec![outpoint.into()], vec![]);
    let block_height = BlockHeight::new(rng.gen());

    let res = check_reward_inputs_outputs_purposes(
        &chain_config,
        &block.block_reward_transactable(),
        &utxo_db,
        block.get_id(),
        block_height,
    )
    .unwrap_err();
    assert_eq!(
        res,
        ConnectTransactionError::SpendStakeError(SpendStakeError::NoBlockRewardOutputs)
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reward_none_to_any(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = chain::config::Builder::test_chain().build();
    let best_block_id: Id<GenBlock> = Id::new(H256::random_using(&mut rng));
    let utxo_db = UtxosDBInMemoryImpl::new(best_block_id, BTreeMap::new());
    let block_height = BlockHeight::new(rng.gen());

    {
        // valid cases
        let valid_purposes = [lock_then_transfer()];

        let number_of_outputs = rng.gen_range(1..10);
        let outputs = get_random_outputs_combination(&mut rng, &valid_purposes, number_of_outputs);
        let block = make_block_no_kernel(outputs);

        check_reward_inputs_outputs_purposes(
            &chain_config,
            &block.block_reward_transactable(),
            &utxo_db,
            block.get_id(),
            block_height,
        )
        .unwrap();
    }

    {
        // invalid cases
        let invalid_purposes = invalid_block_reward_for_pow();

        let number_of_outputs = rng.gen_range(1..10);
        let outputs =
            get_random_outputs_combination(&mut rng, &invalid_purposes, number_of_outputs);
        let block = make_block_no_kernel(outputs);

        let res = check_reward_inputs_outputs_purposes(
            &chain_config,
            &block.block_reward_transactable(),
            &utxo_db,
            block.get_id(),
            block_height,
        )
        .unwrap_err();
        assert_eq!(
            res,
            ConnectTransactionError::IOPolicyError(
                IOPolicyError::InvalidOutputTypeInReward,
                block.get_id().into()
            )
        );
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reward_many_to_none(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = chain::config::Builder::test_chain().build();
    let all_purposes = super::outputs_utils::all_outputs();

    let number_of_outputs = rng.gen_range(2..10);
    let kernel_outputs = get_random_outputs_combination(&mut rng, &all_purposes, number_of_outputs)
        .into_iter()
        .enumerate()
        .map(|(i, output)| {
            (
                UtxoOutPoint::new(
                    OutPointSourceId::BlockReward(Id::new(H256::zero())),
                    i as u32,
                ),
                Utxo::new_for_mempool(output),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let inputs: Vec<TxInput> = kernel_outputs.keys().map(|k| k.clone().into()).collect();
    let best_block_id: Id<GenBlock> = Id::new(H256::random_using(&mut rng));
    let utxo_db = UtxosDBInMemoryImpl::new(best_block_id, kernel_outputs);

    let block = make_block(inputs, vec![]);
    let block_height = BlockHeight::new(rng.gen());

    let res = check_reward_inputs_outputs_purposes(
        &chain_config,
        &block.block_reward_transactable(),
        &utxo_db,
        block.get_id(),
        block_height,
    )
    .unwrap_err();
    assert_eq!(
        res,
        ConnectTransactionError::SpendStakeError(SpendStakeError::ConsensusPoSError(
            consensus::ConsensusPoSError::MultipleKernels
        ))
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reward_accounts_in_inputs(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = chain::config::Builder::test_chain().build();
    let number_of_inputs = rng.gen_range(1..10);
    let number_of_outputs = rng.gen_range(1..10);

    let invalid_inputs = all_account_inputs();
    let valid_outputs = [lock_then_transfer()];

    let invalid_inputs = {
        let mut outputs =
            get_random_inputs_combination(&mut rng, &invalid_inputs, number_of_inputs);
        outputs.shuffle(&mut rng);
        outputs
    };
    let outputs = get_random_outputs_combination(&mut rng, &valid_outputs, number_of_outputs);

    let best_block_id: Id<GenBlock> = Id::new(H256::random_using(&mut rng));
    let utxo_db = UtxosDBInMemoryImpl::new(best_block_id, BTreeMap::new());

    let block = make_block(invalid_inputs, outputs);
    let block_height = BlockHeight::new(rng.gen());

    assert_eq!(
        check_reward_inputs_outputs_purposes(
            &chain_config,
            &block.block_reward_transactable(),
            &utxo_db,
            block.get_id(),
            block_height
        )
        .unwrap_err(),
        ConnectTransactionError::IOPolicyError(
            IOPolicyError::AttemptToUseAccountInputInReward,
            block.get_id().into(),
        )
    );
}

// Check that modifying staker destination in ProduceBlockFromStake is allowed before the corresponding
// fork and prohibited afterwards.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn staker_destination_change(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let fork_height = BlockHeight::new(rng.gen_range(1..1_000_000));

    let chain_config = chain::config::Builder::test_chain()
        .chainstate_upgrades(
            NetUpgrades::initialize(vec![
                (
                    BlockHeight::zero(),
                    ChainstateUpgradeBuilder::latest()
                        .staker_destination_update_forbidden(StakerDestinationUpdateForbidden::No)
                        .build(),
                ),
                (
                    fork_height,
                    ChainstateUpgradeBuilder::latest()
                        .staker_destination_update_forbidden(StakerDestinationUpdateForbidden::Yes)
                        .build(),
                ),
            ])
            .unwrap(),
        )
        .build();

    let old_staker_dest =
        Destination::PublicKey(PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr).1);
    let new_staker_dest =
        Destination::PublicKey(PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr).1);
    let stake_pool_data = StakePoolData::new(
        Amount::ZERO,
        old_staker_dest.clone(),
        VRF_KEYS.1.clone(),
        Destination::AnyoneCanSpend,
        PerThousand::new(0).unwrap(),
        Amount::ZERO,
    );

    let kernel_input_utxo = if rng.gen_bool(0.5) {
        TxOutput::CreateStakePool(stake_pool_id(), Box::new(stake_pool_data.clone()))
    } else {
        TxOutput::ProduceBlockFromStake(old_staker_dest, stake_pool_id())
    };

    let kernel_input_outpoint =
        UtxoOutPoint::new(OutPointSourceId::Transaction(Id::new(H256::zero())), 0);
    let utxo_db = UtxosDBInMemoryImpl::new(
        Id::<GenBlock>::new(H256::zero()),
        BTreeMap::from_iter([(
            kernel_input_outpoint.clone(),
            Utxo::new_for_mempool(kernel_input_utxo.clone()),
        )]),
    );

    let reward_output = TxOutput::ProduceBlockFromStake(new_staker_dest, stake_pool_id());
    let block = make_block(
        vec![kernel_input_outpoint.into()],
        vec![reward_output.clone()],
    );

    // Case 1 - before the fork; the staker destination change is allowed.
    {
        let block_height = if rng.gen_bool(0.5) {
            fork_height.prev_height().unwrap()
        } else {
            BlockHeight::new(rng.gen_range(0..fork_height.into_int()))
        };

        let result = check_reward_inputs_outputs_purposes(
            &chain_config,
            &block.block_reward_transactable(),
            &utxo_db,
            block.get_id(),
            block_height,
        );

        assert_matches!(result, Ok(_));
    }

    // Case 2 - after the fork; the staker destination change is prohibited.
    {
        let block_height = if rng.gen_bool(0.5) {
            fork_height
        } else {
            BlockHeight::new(rng.gen_range(fork_height.into_int()..=BlockHeight::max().into_int()))
        };

        let result = check_reward_inputs_outputs_purposes(
            &chain_config,
            &block.block_reward_transactable(),
            &utxo_db,
            block.get_id(),
            block_height,
        );

        assert_matches!(
            result,
            Err(ConnectTransactionError::ProduceBlockFromStakeChangesStakerDestination(_, _))
        );
    }
}
