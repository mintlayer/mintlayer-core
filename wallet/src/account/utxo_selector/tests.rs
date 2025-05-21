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
    chain::{output_value::OutputValue, Destination, GenBlock, OutPointSourceId, UtxoOutPoint},
    primitives::Id,
    Uint256,
};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

use super::*;

fn add_output(value: Amount, groups: &mut Vec<OutputGroup>) {
    let outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(Id::<GenBlock>::new(Uint256::from_u64(1).into())),
        0,
    );
    let tx_output = TxOutput::Transfer(OutputValue::Coin(value), Destination::AnyoneCanSpend);

    let outputs = vec![(outpoint.into(), tx_output)];

    groups.push(OutputGroup {
        outputs,
        value,
        fee: Amount::ZERO,
        long_term_fee: Amount::ZERO,
        weight: 1,
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_knapsack_solver_empty(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let mut groups = vec![];
    let target_value = Amount::from_atoms(1);
    let cost_of_change = Amount::ZERO;
    let max_weight = 100;
    let error = knapsack_solver(
        &mut groups,
        target_value,
        cost_of_change,
        &mut rng,
        max_weight,
        PayFee::PayFeeWithThisCurrency,
    )
    .err()
    .unwrap();

    assert_eq!(error, UtxoSelectorError::NoSolutionFound);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_knapsack_solver_not_enough(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let mut groups = vec![];
    let mut target_value = Amount::ZERO;
    for _ in 0..rng.gen_range(1..100) {
        let value = Amount::from_atoms(rng.gen_range(1..100));
        add_output(value, &mut groups);
        target_value = (target_value + value).expect("can't overflow");
    }

    target_value = (target_value + Amount::from_atoms(1)).unwrap();

    let cost_of_change = Amount::ZERO;
    let max_weight = 100;
    let error = knapsack_solver(
        &mut groups,
        target_value,
        cost_of_change,
        &mut rng,
        max_weight,
        PayFee::PayFeeWithThisCurrency,
    )
    .err()
    .unwrap();

    assert_eq!(error, UtxoSelectorError::NoSolutionFound);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_knapsack_solver_max_weight(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let mut groups = vec![];
    let mut target_value = Amount::ZERO;
    let num_inputs = rng.gen_range(1..100);
    for _ in 0..num_inputs {
        let value = Amount::from_atoms(rng.gen_range(1..100));
        add_output(value, &mut groups);
        target_value = (target_value + value).expect("can't overflow");
    }

    let cost_of_change = Amount::ZERO;
    // make sure there cannot be a solution because it requires all inputs but the max weight does
    // not allow to select them all
    let max_weight = num_inputs - 1;
    let result = knapsack_solver(
        &mut groups,
        target_value,
        cost_of_change,
        &mut rng,
        max_weight,
        PayFee::PayFeeWithThisCurrency,
    );

    assert_eq!(result.unwrap_err(), UtxoSelectorError::MaxWeightExceeded);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_knapsack_solver_exact_solution(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let target_value = Amount::from_atoms(rng.gen_range(1..100));
    let mut groups = vec![];
    for _ in 0..rng.gen_range(0..100) {
        // add values different from the target_value
        let mut value = Amount::from_atoms(rng.gen_range(1..100));
        while value == target_value {
            value = Amount::from_atoms(rng.gen_range(1..100));
        }
        add_output(value, &mut groups);
    }

    // add the target value itself
    add_output(target_value, &mut groups);

    let cost_of_change = Amount::ZERO;
    let max_weight = 100;
    let result = knapsack_solver(
        &mut groups,
        target_value,
        cost_of_change,
        &mut rng,
        max_weight,
        PayFee::PayFeeWithThisCurrency,
    )
    .unwrap();

    // found exact match
    assert_eq!(result.effective_value, target_value);
    assert_eq!(result.outputs.len(), 1);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_knapsack_solver_exact_solution_multiple_utxos(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let mut groups = vec![];
    let mut target_value = Amount::ZERO;
    for _ in 0..rng.gen_range(1..100) {
        let value = Amount::from_atoms(rng.gen_range(1..100));
        add_output(value, &mut groups);

        // randomly add to the target_value so we know there is an exact match from a subset of the
        // groups
        if rng.gen::<bool>() || target_value == Amount::ZERO {
            target_value = (target_value + value).expect("can't overflow");
        }
    }

    let cost_of_change = Amount::ZERO;
    let max_weight = 100;
    let result = knapsack_solver(
        &mut groups,
        target_value,
        cost_of_change,
        &mut rng,
        max_weight,
        PayFee::PayFeeWithThisCurrency,
    )
    .unwrap();

    // found exact match
    assert_eq!(result.effective_value, target_value);
    assert!(!result.outputs.is_empty());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_knapsack_solver_not_exact_solution(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut groups = vec![];
    for value in [1, 2, 5, 10, 20] {
        add_output(Amount::from_atoms(value), &mut groups);
    }

    // cannot make 34 from the above values but can make 35
    let target_value = Amount::from_atoms(34);
    let cost_of_change = Amount::from_atoms(1);
    let max_weight = 100;
    let result = knapsack_solver(
        &mut groups,
        target_value,
        cost_of_change,
        &mut make_pseudo_rng(),
        max_weight,
        PayFee::PayFeeWithThisCurrency,
    )
    .unwrap();

    assert_eq!(result.effective_value, Amount::from_atoms(35));
    assert_eq!(result.outputs.len(), 3);

    // cannot make 9 from [1,2,5] will use lowest larger value which is 10
    let target_value = Amount::from_atoms(9);
    let pay_fees = if rng.gen::<bool>() {
        PayFee::PayFeeWithThisCurrency
    } else {
        PayFee::DoNotPayFeeWithThisCurrency
    };
    let mut result = knapsack_solver(
        &mut groups,
        target_value,
        cost_of_change,
        &mut make_pseudo_rng(),
        max_weight,
        pay_fees,
    )
    .unwrap();
    result
        .compute_and_set_waste(cost_of_change, cost_of_change, cost_of_change, pay_fees)
        .unwrap();

    // found exact match
    assert_eq!(result.effective_value, Amount::from_atoms(10));
    assert_eq!(result.outputs.len(), 1);
    match pay_fees {
        PayFee::PayFeeWithThisCurrency => {
            assert_eq!(result.change, Amount::from_atoms(0));
        }
        PayFee::DoNotPayFeeWithThisCurrency => {
            assert_eq!(result.change, Amount::from_atoms(1));
        }
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_bnb_solver_exact_solution(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let target_value = Amount::from_atoms(rng.gen_range(1..100));
    let mut groups = vec![];
    for _ in 0..rng.gen_range(0..100) {
        // add values different from the target_value
        let mut value = Amount::from_atoms(rng.gen_range(1..100));
        while value == target_value {
            value = Amount::from_atoms(rng.gen_range(1..100));
        }
        add_output(value, &mut groups);
    }

    // add the target value itself
    add_output(target_value, &mut groups);

    let cost_of_change = Amount::ZERO;
    let max_weight = 100;
    let result = select_coins_bnb(
        groups,
        target_value,
        cost_of_change,
        max_weight,
        PayFee::PayFeeWithThisCurrency,
    )
    .unwrap();

    // found exact match
    assert_eq!(result.effective_value, target_value);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_bnb_solver_max_weight(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let mut groups = vec![];
    let mut target_value = Amount::ZERO;
    let num_inputs = rng.gen_range(1..100);
    for _ in 0..num_inputs {
        let value = Amount::from_atoms(rng.gen_range(1..100));
        add_output(value, &mut groups);
        target_value = (target_value + value).expect("can't overflow");
    }

    let cost_of_change = Amount::ZERO;
    // make sure there cannot be a solution because it requires all inputs but the max weight does
    // not allow to select them all
    let max_weight = num_inputs - 1;
    let result = select_coins_bnb(
        groups,
        target_value,
        cost_of_change,
        max_weight,
        PayFee::PayFeeWithThisCurrency,
    );

    assert_eq!(result.unwrap_err(), UtxoSelectorError::MaxWeightExceeded);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_bnb_solver_exact_solution_multiple_utxos(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let mut groups = vec![];
    let mut target_value = Amount::ZERO;
    for _ in 0..rng.gen_range(1..100) {
        let value = Amount::from_atoms(rng.gen_range(1..100));
        add_output(value, &mut groups);

        // randomly add to the target_value so we know there is an exact match from a subset of the
        // groups
        if rng.gen::<bool>() || target_value == Amount::ZERO {
            target_value = (target_value + value).expect("can't overflow");
        }
    }

    let cost_of_change = Amount::ZERO;
    let max_weight = 100;
    let result = select_coins_bnb(
        groups,
        target_value,
        cost_of_change,
        max_weight,
        PayFee::PayFeeWithThisCurrency,
    )
    .unwrap();

    // found exact match
    assert!(!result.outputs.is_empty());
    assert_eq!(result.effective_value, target_value);
}

#[test]
fn test_bnb_solver_not_exact_solution_fail() {
    let mut groups = vec![];
    for value in [1, 2, 5, 10, 20] {
        add_output(Amount::from_atoms(value), &mut groups);
    }

    // cannot make 34 from the above values but can make 35
    let target_value = Amount::from_atoms(34);
    let cost_of_change = Amount::from_atoms(2);
    let max_weight = 100;
    let result = select_coins_bnb(
        groups.clone(),
        target_value,
        cost_of_change,
        max_weight,
        PayFee::PayFeeWithThisCurrency,
    )
    .unwrap();

    assert_eq!(result.effective_value, Amount::from_atoms(35));
    assert_eq!(result.outputs.len(), 3);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_srd_solver_find_solution(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let target_value = Amount::from_atoms(rng.gen_range(1..100));
    let mut groups = vec![];
    for _ in 0..rng.gen_range(0..100) {
        // add values different from the target_value
        let mut value = Amount::from_atoms(rng.gen_range(1..100));
        while value == target_value {
            value = Amount::from_atoms(rng.gen_range(1..100));
        }
        add_output(value, &mut groups);
    }

    // add the target value itself
    add_output(target_value, &mut groups);

    let cost_of_change = Amount::ZERO;
    let max_weight = 100;
    let result = select_coins_srd(
        &groups,
        target_value,
        &mut rng,
        cost_of_change,
        max_weight,
        PayFee::PayFeeWithThisCurrency,
    )
    .unwrap();

    assert!(result.effective_value >= target_value);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_srd_solver_max_weight(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let mut groups = vec![];
    let mut target_value = Amount::ZERO;
    let num_inputs = rng.gen_range(1..100);
    for _ in 0..num_inputs {
        let value = Amount::from_atoms(rng.gen_range(1..100));
        add_output(value, &mut groups);
        target_value = (target_value + value).expect("can't overflow");
    }

    let cost_of_change = Amount::ZERO;
    // make sure there cannot be a solution because it requires all inputs but the max weight does
    // not allow to select them all
    let max_weight = num_inputs - 1;
    let result = select_coins_srd(
        &groups,
        target_value,
        &mut rng,
        cost_of_change,
        max_weight,
        PayFee::PayFeeWithThisCurrency,
    );

    assert_eq!(result.unwrap_err(), UtxoSelectorError::MaxWeightExceeded);
}
