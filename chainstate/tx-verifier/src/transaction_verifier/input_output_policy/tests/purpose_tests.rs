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

use super::outputs_utils::*;
use super::purposes_check::*;
use super::*;

use crate::error::SpendStakeError;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tx_stake_multiple_pools(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let source_inputs = super::outputs_utils::valid_tx_inputs();
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

    let source_inputs = super::outputs_utils::valid_tx_inputs();
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

    let valid_inputs =
        [lock_then_transfer(), transfer(), stake_pool(), produce_block(), issue_nft()];
    let valid_outputs = [
        lock_then_transfer(),
        transfer(),
        burn(),
        delegate_staking(),
        issue_tokens(),
        issue_nft(),
    ];

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
fn tx_many_to_many_invalid_inputs(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let number_of_inputs = rng.gen_range(1..10);
    let number_of_outputs = rng.gen_range(1..10);

    let valid_inputs = super::outputs_utils::valid_tx_inputs();
    let valid_outputs = super::outputs_utils::valid_tx_outputs();

    let invalid_inputs = [burn(), delegate_staking(), create_delegation(), issue_tokens()];

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

    let valid_inputs = super::outputs_utils::valid_tx_inputs();
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
#[trace]
#[case(Seed::from_entropy())]
fn reward_one_to_one(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let all_outputs = super::outputs_utils::all_outputs();
    let input_utxo = get_random_outputs_combination(&mut rng, &all_outputs, 1)[0].clone();
    let output = get_random_outputs_combination(&mut rng, &all_outputs, 1)[0].clone();

    let outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(Id::new(H256::zero())), 0);
    let utxo_db = UtxosDBInMemoryImpl::new(
        Id::<GenBlock>::new(H256::zero()),
        BTreeMap::from_iter([(outpoint.clone(), Utxo::new_for_mempool(input_utxo.clone()))]),
    );

    let block = make_block(vec![outpoint.into()], vec![output.clone()]);

    let result = check_reward_inputs_outputs_purposes(
        &block.block_reward_transactable(),
        &utxo_db,
        block.get_id(),
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
            issue_nft(),
            issue_tokens(),
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
