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
    chain::{GenBlock, OutPointSourceId, TxInput, UtxoOutPoint},
    primitives::{Id, H256},
};
use crypto::random::{Rng, SliceRandom};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};
use utxo::{Utxo, UtxosDBInMemoryImpl};

use super::purposes_check::*;
use super::*;

use crate::error::SpendStakeError;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tx_stake_multiple_pools(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let source_inputs = [lock_then_transfer(), transfer()];
    let source_valid_outputs = [lock_then_transfer(), transfer(), burn(), delegate_staking()];
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

    let inputs_utxos = get_inputs_utxos(&utxo_db, tx.inputs()).unwrap();
    let result = check_tx_inputs_outputs_purposes(&tx, &inputs_utxos).unwrap_err();
    assert_eq!(result, IOPolicyError::MultiplePoolCreated);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tx_create_multiple_delegations(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let source_inputs = [lock_then_transfer(), transfer()];
    let source_valid_outputs = [lock_then_transfer(), transfer(), burn(), delegate_staking()];
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

    let inputs_utxos = get_inputs_utxos(&utxo_db, tx.inputs()).unwrap();
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

    // valid cases
    let valid_inputs = [lock_then_transfer(), transfer(), stake_pool(), produce_block()];
    let valid_outputs = [lock_then_transfer(), transfer(), burn(), delegate_staking()];

    let (utxo_db, tx) = prepare_utxos_and_tx_with_random_combinations(
        &mut rng,
        &valid_inputs,
        number_of_inputs,
        &valid_outputs,
        number_of_outputs,
        None,
    );
    let inputs_utxos = get_inputs_utxos(&utxo_db, tx.inputs()).unwrap();
    check_tx_inputs_outputs_purposes(&tx, &inputs_utxos).unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tx_many_to_many_invalid(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let number_of_inputs = rng.gen_range(1..10);
    let number_of_outputs = rng.gen_range(1..10);

    let valid_inputs = [lock_then_transfer(), transfer(), stake_pool(), produce_block()];
    let valid_outputs = [lock_then_transfer(), transfer(), burn(), delegate_staking()];

    let invalid_inputs = [burn(), delegate_staking(), create_delegation()];

    let input_utxos = {
        let mut outputs =
            get_random_outputs_combination(&mut rng, &invalid_inputs, number_of_inputs)
                .into_iter()
                .chain(valid_inputs.into_iter())
                .collect::<Vec<_>>();
        outputs.shuffle(&mut rng);
        outputs
    };

    let outputs = get_random_outputs_combination(&mut rng, &valid_outputs, number_of_outputs);
    let (utxo_db, tx) = prepare_utxos_and_tx(&mut rng, input_utxos, outputs);
    let inputs_utxos = get_inputs_utxos(&utxo_db, tx.inputs()).unwrap();

    assert_eq!(
        check_tx_inputs_outputs_purposes(&tx, &inputs_utxos).unwrap_err(),
        IOPolicyError::InvalidInputTypeInTx,
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tx_produce_block_in_output(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let number_of_inputs = rng.gen_range(1..10);
    let number_of_outputs = rng.gen_range(1..10);

    let valid_inputs = [lock_then_transfer(), transfer(), stake_pool(), produce_block()];
    let valid_outputs = [lock_then_transfer(), transfer(), burn(), delegate_staking()];

    let invalid_outputs = [produce_block()];

    let input_utxos = get_random_outputs_combination(&mut rng, &valid_inputs, number_of_inputs);

    let outputs = {
        let mut outputs =
            get_random_outputs_combination(&mut rng, &invalid_outputs, number_of_outputs)
                .into_iter()
                .chain(valid_outputs.into_iter())
                .collect::<Vec<_>>();
        outputs.shuffle(&mut rng);
        outputs
    };

    let (utxo_db, tx) = prepare_utxos_and_tx(&mut rng, input_utxos, outputs);
    let inputs_utxos = get_inputs_utxos(&utxo_db, tx.inputs()).unwrap();

    assert_eq!(
        check_tx_inputs_outputs_purposes(&tx, &inputs_utxos).unwrap_err(),
        IOPolicyError::ProduceBlockInTx,
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tx_create_pool_and_delegation_same_tx(#[case] seed: Seed) {
    let source_inputs = [transfer(), lock_then_transfer()];
    let outputs = [stake_pool(), create_delegation()];

    let mut rng = make_seedable_rng(seed);
    let number_of_inputs = rng.gen_range(2..10);
    let input_utxos = get_random_outputs_combination(&mut rng, &source_inputs, number_of_inputs);

    let (utxo_db, tx) = prepare_utxos_and_tx(&mut rng, input_utxos, outputs.to_vec());
    let inputs_utxos = get_inputs_utxos(&utxo_db, tx.inputs()).unwrap();
    assert_eq!(check_tx_inputs_outputs_purposes(&tx, &inputs_utxos), Ok(()));
}

#[rstest]
#[rustfmt::skip]
#[case(transfer(), transfer(),           Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(transfer(), burn(),               Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(transfer(), lock_then_transfer(), Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(transfer(), stake_pool(),         Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(transfer(), produce_block(),      Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(transfer(), create_delegation(),  Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(transfer(), delegate_staking(),   Err(IOPolicyError::InvalidInputTypeInReward))]
/*-----------------------------------------------------------------------------------------------*/
#[case(burn(), transfer(),           Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(burn(), burn(),               Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(burn(), lock_then_transfer(), Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(burn(), stake_pool(),         Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(burn(), produce_block(),      Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(burn(), create_delegation(),  Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(burn(), delegate_staking(),   Err(IOPolicyError::InvalidInputTypeInReward))]
/*-----------------------------------------------------------------------------------------------*/
#[case(lock_then_transfer(), transfer(),           Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(lock_then_transfer(), burn(),               Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(lock_then_transfer(), lock_then_transfer(), Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(lock_then_transfer(), stake_pool(),         Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(lock_then_transfer(), produce_block(),      Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(lock_then_transfer(), create_delegation(),  Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(lock_then_transfer(), delegate_staking(),   Err(IOPolicyError::InvalidInputTypeInReward))]
/*-----------------------------------------------------------------------------------------------*/
#[case(stake_pool(), transfer(),           Err(IOPolicyError::InvalidOutputTypeInReward))]
#[case(stake_pool(), burn(),               Err(IOPolicyError::InvalidOutputTypeInReward))]
#[case(stake_pool(), lock_then_transfer(), Err(IOPolicyError::InvalidOutputTypeInReward))]
#[case(stake_pool(), stake_pool(),         Err(IOPolicyError::InvalidOutputTypeInReward))]
#[case(stake_pool(), produce_block(),      Ok(()))]
#[case(stake_pool(), create_delegation(),  Err(IOPolicyError::InvalidOutputTypeInReward))]
#[case(stake_pool(), delegate_staking(),   Err(IOPolicyError::InvalidOutputTypeInReward))]
/*-----------------------------------------------------------------------------------------------*/
#[case(produce_block(), transfer(),           Err(IOPolicyError::InvalidOutputTypeInReward))]
#[case(produce_block(), burn(),               Err(IOPolicyError::InvalidOutputTypeInReward))]
#[case(produce_block(), lock_then_transfer(), Err(IOPolicyError::InvalidOutputTypeInReward))]
#[case(produce_block(), stake_pool(),         Err(IOPolicyError::InvalidOutputTypeInReward))]
#[case(produce_block(), produce_block(),      Ok(()))]
#[case(
    produce_block(),
    create_delegation(),
    Err(IOPolicyError::InvalidOutputTypeInReward)
)]
#[case(
    produce_block(),
    delegate_staking(),
    Err(IOPolicyError::InvalidOutputTypeInReward)
)]
/*-----------------------------------------------------------------------------------------------*/
#[case(create_delegation(), transfer(),           Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(create_delegation(), burn(),               Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(create_delegation(), lock_then_transfer(), Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(create_delegation(), stake_pool(),         Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(create_delegation(), produce_block(),      Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(create_delegation(), create_delegation(),  Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(create_delegation(), delegate_staking(),   Err(IOPolicyError::InvalidInputTypeInReward))]
/*-----------------------------------------------------------------------------------------------*/
#[case(delegate_staking(), transfer(),           Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(delegate_staking(), burn(),               Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(delegate_staking(), lock_then_transfer(), Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(delegate_staking(), stake_pool(),         Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(delegate_staking(), produce_block(),      Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(delegate_staking(), create_delegation(),  Err(IOPolicyError::InvalidInputTypeInReward))]
#[case(delegate_staking(), delegate_staking(),   Err(IOPolicyError::InvalidInputTypeInReward))]
fn reward_one_to_one(
    #[case] input_utxo: TxOutput,
    #[case] output: TxOutput,
    #[case] result: Result<(), IOPolicyError>,
) {
    let outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(Id::new(H256::zero())), 0);
    let utxo_db = UtxosDBInMemoryImpl::new(
        Id::<GenBlock>::new(H256::zero()),
        BTreeMap::from_iter([(outpoint.clone(), Utxo::new_for_mempool(input_utxo))]),
    );

    let block = make_block(vec![outpoint.into()], vec![output]);

    assert_eq!(
        result.map_err(|e| ConnectTransactionError::IOPolicyError(e, block.get_id().into())),
        check_reward_inputs_outputs_purposes(
            &block.block_reward_transactable(),
            &utxo_db,
            block.get_id()
        )
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reward_one_to_none(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

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

    let res = check_reward_inputs_outputs_purposes(
        &block.block_reward_transactable(),
        &utxo_db,
        block.get_id(),
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
    let best_block_id: Id<GenBlock> = Id::new(H256::random_using(&mut rng));
    let utxo_db = UtxosDBInMemoryImpl::new(best_block_id, BTreeMap::new());

    {
        // valid cases
        let valid_purposes = [lock_then_transfer()];

        let number_of_outputs = rng.gen_range(1..10);
        let outputs = get_random_outputs_combination(&mut rng, &valid_purposes, number_of_outputs);
        let block = make_block_no_kernel(outputs);

        check_reward_inputs_outputs_purposes(
            &block.block_reward_transactable(),
            &utxo_db,
            block.get_id(),
        )
        .unwrap();
    }

    {
        // invalid cases
        let invalid_purposes = [
            transfer(),
            burn(),
            stake_pool(),
            produce_block(),
            create_delegation(),
            delegate_staking(),
        ];

        let number_of_outputs = rng.gen_range(1..10);
        let outputs =
            get_random_outputs_combination(&mut rng, &invalid_purposes, number_of_outputs);
        let block = make_block_no_kernel(outputs);

        let res = check_reward_inputs_outputs_purposes(
            &block.block_reward_transactable(),
            &utxo_db,
            block.get_id(),
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

    let all_purposes = [
        lock_then_transfer(),
        transfer(),
        burn(),
        stake_pool(),
        produce_block(),
        create_delegation(),
        delegate_staking(),
    ];

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

    let res = check_reward_inputs_outputs_purposes(
        &block.block_reward_transactable(),
        &utxo_db,
        block.get_id(),
    )
    .unwrap_err();
    assert_eq!(
        res,
        ConnectTransactionError::SpendStakeError(SpendStakeError::ConsensusPoSError(
            consensus::ConsensusPoSError::MultipleKernels
        ))
    );
}
