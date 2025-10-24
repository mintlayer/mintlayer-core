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

use std::collections::BinaryHeap;

pub mod output_group;
pub use output_group::{OutputGroup, PayFee};

use common::{
    chain::{TxInput, TxOutput},
    primitives::{amount::SignedAmount, Amount},
};
use randomness::{make_pseudo_rng, Rng, SliceRandom};
use utils::ensure;

const TOTAL_TRIES: u32 = 100_000;

#[derive(Debug)]
pub struct SelectionResult {
    outputs: Vec<(TxInput, TxOutput)>,
    effective_value: Amount,
    target: Amount,
    waste: SignedAmount,
    weight: usize,
    fees: Amount,
    change: Amount,
}

impl SelectionResult {
    fn new(target: Amount) -> SelectionResult {
        SelectionResult {
            outputs: vec![],
            effective_value: Amount::ZERO,
            target,
            waste: SignedAmount::ZERO,
            weight: 0,
            fees: Amount::ZERO,
            change: Amount::ZERO,
        }
    }

    pub fn get_weight(&self) -> usize {
        self.weight
    }

    pub fn get_total_fees(&self) -> Amount {
        self.fees
    }

    pub fn get_change(&self) -> Amount {
        self.change
    }

    pub fn add_change(mut self, change: Amount) -> Result<Self, UtxoSelectorError> {
        self.change = (self.change + change).ok_or(UtxoSelectorError::AmountArithmeticError)?;
        Ok(self)
    }

    pub fn into_output_pairs(self) -> Vec<(TxInput, TxOutput)> {
        self.outputs
    }

    pub fn num_selected_inputs(&self) -> usize {
        self.outputs.len()
    }

    fn add_input(
        &mut self,
        group: &OutputGroup,
        pay_fees: PayFee,
    ) -> Result<(), UtxoSelectorError> {
        self.effective_value = (self.effective_value + group.get_effective_value(pay_fees))
            .ok_or(UtxoSelectorError::AmountArithmeticError)?;
        // Always consider the cost of spending an input now vs in the future.
        self.waste = group
            .fee
            .into_signed()
            .and_then(|fee| {
                group.long_term_fee.into_signed().and_then(|long_term_fee| fee - long_term_fee)
            })
            .and_then(|fee_difference| self.waste + fee_difference)
            .ok_or(UtxoSelectorError::AmountArithmeticError)?;

        self.outputs.extend(group.outputs.iter().cloned());
        self.weight += group.weight;
        self.fees = (self.fees + group.fee).ok_or(UtxoSelectorError::AmountArithmeticError)?;
        Ok(())
    }

    fn compute_and_set_waste(
        &mut self,
        min_viable_change: Amount,
        change_cost: Amount,
        change_fee: Amount,
        pay_fees: PayFee,
    ) -> Result<(), UtxoSelectorError> {
        self.change = self.calculate_change(min_viable_change, change_fee, pay_fees);

        if self.change != Amount::ZERO {
            // Consider the cost of making change and spending it in the future
            // If we aren't making change, the caller should've set change_cost to 0
            self.waste = change_cost
                .into_signed()
                .and_then(|change_cost| self.waste + change_cost)
                .ok_or(UtxoSelectorError::AmountArithmeticError)?;
        } else {
            // When we are not making change (change_cost == 0), consider the excess we are throwing away to fees
            self.waste = (self.effective_value - self.target)
                .expect("effective_value is larger tha target")
                .into_signed()
                .and_then(|value_difference| self.waste + value_difference)
                .ok_or(UtxoSelectorError::AmountArithmeticError)?;
        }

        Ok(())
    }

    fn calculate_change(
        &self,
        min_viable_change: Amount,
        change_fee: Amount,
        pay_fees: PayFee,
    ) -> Amount {
        // change = SUM(inputs) - SUM(outputs) - fees
        // 1) With SFFO we don't pay any fees
        // 2) Otherwise we pay all the fees:
        //  - input fees are covered by effective_value
        //  - non_input_fee is included in target
        //  - change_fee
        let change =
            (self.effective_value - self.target).expect("effective value is larger than target");

        let change = match pay_fees {
            PayFee::PayFeeWithThisCurrency => (change - change_fee).unwrap_or(Amount::ZERO),
            PayFee::DoNotPayFeeWithThisCurrency => change,
        };

        if change < min_viable_change {
            Amount::ZERO
        } else {
            change
        }
    }

    fn clear(&mut self) {
        self.weight = 0;
        self.waste = SignedAmount::ZERO;
        self.outputs.clear();
        self.effective_value = Amount::ZERO;
        self.fees = Amount::ZERO;
    }
}

#[derive(thiserror::Error, Debug, Eq, PartialEq, Clone)]
pub enum UtxoSelectorError {
    #[error("No solution found")]
    NoSolutionFound,
    #[error("No available UTXOs")]
    NoUtxos,
    #[error("Not enough funds got: {0:?}, requested: {1:?}")]
    NotEnoughFunds(Amount, Amount),
    #[error("The inputs size exceeds the maximum weight.")]
    MaxWeightExceeded,
    #[error("Unsupported transaction output type")] // TODO implement display for TxOutput
    UnsupportedTransactionOutput(Box<TxOutput>),
    #[error("Amount arithmetic error")]
    AmountArithmeticError,
}

struct OutputGroupOrd(OutputGroup, PayFee);

impl PartialEq for OutputGroupOrd {
    fn eq(&self, other: &Self) -> bool {
        self.0.get_effective_value(self.1).eq(&other.0.get_effective_value(self.1))
    }
}

impl PartialOrd for OutputGroupOrd {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for OutputGroupOrd {}

impl Ord for OutputGroupOrd {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.get_effective_value(self.1).cmp(&other.0.get_effective_value(self.1))
    }
}

/// Select coins by Single Random Draw. OutputGroups are selected randomly from the eligible
/// outputs until the target is satisfied
fn select_coins_srd(
    utxo_pool: &[OutputGroup],
    target_value: Amount,
    rng: &mut impl Rng,
    change_cost: Amount,
    max_weight: usize,
    pay_fees: PayFee,
) -> Result<SelectionResult, UtxoSelectorError> {
    let mut result = SelectionResult::new(target_value);
    let mut heap = BinaryHeap::new();

    // Include change for SRD as we want to avoid making really small change if the selection just
    // barely meets the target. Just use the lower bound change target instead of the randomly
    // generated one, since SRD will result in a random change amount anyway; avoid making the
    // target needlessly large.
    let target_value =
        (target_value + change_cost).ok_or(UtxoSelectorError::AmountArithmeticError)?;

    let mut indexes: Vec<usize> = (0..utxo_pool.len()).collect();
    indexes.shuffle(rng);

    let mut selected_eff_value = Amount::ZERO;
    let mut weight = 0;
    let mut max_tx_weight_exceeded = false;

    for &i in indexes.iter() {
        let group = &utxo_pool[i];

        // Add group to selection
        heap.push(OutputGroupOrd(group.clone(), pay_fees));
        selected_eff_value = (selected_eff_value + group.get_effective_value(pay_fees))
            .ok_or(UtxoSelectorError::AmountArithmeticError)?;
        weight += group.weight;

        // If the selection weight exceeds the maximum allowed size, remove the least valuable inputs until we
        // are below max weight.
        if weight > max_weight {
            max_tx_weight_exceeded = true; // mark it in case we don't find any useful result.
            while let Some(group) = heap.pop() {
                if weight <= max_weight {
                    break;
                }
                selected_eff_value = (selected_eff_value - group.0.get_effective_value(pay_fees))
                    .ok_or(UtxoSelectorError::AmountArithmeticError)?;
                weight -= group.0.weight;
            }
        }

        // Now check if we are above the target
        if selected_eff_value >= target_value {
            // Result found, add it.
            while let Some(group) = heap.pop() {
                result.add_input(&group.0, pay_fees)?;
            }
            return Ok(result);
        }
    }

    Err(if max_tx_weight_exceeded {
        UtxoSelectorError::MaxWeightExceeded
    } else {
        UtxoSelectorError::NoSolutionFound
    })
}

/// Original coin selection algorithm as a fallback
fn knapsack_solver_impl(
    groups: &mut Vec<OutputGroup>,
    target_value: Amount,
    cost_of_change: Amount,
    rng: &mut impl Rng,
    max_weight: usize,
    pay_fees: PayFee,
) -> Result<SelectionResult, UtxoSelectorError> {
    let mut result = SelectionResult::new(target_value);

    let target_with_change_cost =
        (target_value + cost_of_change).ok_or(UtxoSelectorError::AmountArithmeticError)?;

    let mut lowest_group_larger_than_target: Option<OutputGroup> = None;
    // groups that have effective_value lower than the target
    let mut applicable_groups = Vec::new();
    // the total value of the groups with lower value than the target
    let mut total_lower = Amount::ZERO;

    groups.shuffle(rng);

    for group in groups {
        // in case of perfect match add that one as the result
        if group.get_effective_value(pay_fees) == target_value {
            result.add_input(group, pay_fees)?;
            return Ok(result);
        } else if group.get_effective_value(pay_fees) < target_with_change_cost {
            applicable_groups.push(group.clone());
            total_lower = (total_lower + group.get_effective_value(pay_fees))
                .ok_or(UtxoSelectorError::AmountArithmeticError)?;
        }
        // if group value is > target_with_change_cost check to update lowest_group_larger_than_target
        else if let Some(current_lowest) = lowest_group_larger_than_target.as_ref() {
            if group.get_effective_value(pay_fees) < current_lowest.get_effective_value(pay_fees) {
                lowest_group_larger_than_target = Some(group.clone());
            }
        } else {
            lowest_group_larger_than_target = Some(group.clone());
        }
    }

    // if no perfect match was found check the lower groups

    // if total_lower is the target value add them all as the result
    if total_lower == target_value {
        for group in applicable_groups {
            result.add_input(&group, pay_fees)?;
        }
        return Ok(result);
    }

    // if not enough then check the lowest group that is larger than the target
    if total_lower < target_value {
        if let Some(group) = lowest_group_larger_than_target.as_ref() {
            result.add_input(group, pay_fees)?;
            return Ok(result);
        }
        return Err(UtxoSelectorError::NoSolutionFound);
    }

    // if the total_lower > target_value select a subset

    applicable_groups.sort_by_key(|g| std::cmp::Reverse(g.get_effective_value(pay_fees)));
    let mut best_solution_selected: Vec<bool> = vec![true; applicable_groups.len()];
    let mut best_solution_total = total_lower;

    approximate_best_subset(
        rng,
        &applicable_groups,
        total_lower,
        target_value,
        &mut best_solution_selected,
        &mut best_solution_total,
        pay_fees,
    );
    if best_solution_total != target_value && total_lower >= target_with_change_cost {
        approximate_best_subset(
            rng,
            &applicable_groups,
            total_lower,
            target_with_change_cost,
            &mut best_solution_selected,
            &mut best_solution_total,
            pay_fees,
        );
    }

    match lowest_group_larger_than_target.as_ref() {
        Some(group)
        // If we have a bigger coin and either the stochastic approximation didn't find a good solution,
            if (best_solution_total != target_value && best_solution_total < target_with_change_cost)
        // or the next bigger coin is closer, return the bigger coin
                || group.get_effective_value(pay_fees) <= best_solution_total =>
        {
            result.add_input(group, pay_fees)?;
        }
        _ => {
            for (i, group) in applicable_groups.iter().enumerate() {
                if best_solution_selected[i] {
                    result.add_input(group, pay_fees)?;
                }
            }

            // If the result exceeds the maximum allowed size, return closest UTXO above the target
            if result.weight > max_weight {
                if let Some(group) = lowest_group_larger_than_target.as_ref() {
                    result.clear();
                    result.add_input(group, pay_fees)?;
                } else {
                    // No UTXO above target, nothing to do.
                    return Err(UtxoSelectorError::MaxWeightExceeded);
                }
            }
        }
    }

    Ok(result)
}

fn knapsack_solver(
    groups: &mut Vec<OutputGroup>,
    target_value: Amount,
    cost_of_change: Amount,
    rng: &mut impl Rng,
    max_weight: usize,
    pay_fees: PayFee,
) -> Result<SelectionResult, UtxoSelectorError> {
    let result = knapsack_solver_impl(
        groups,
        target_value,
        cost_of_change,
        rng,
        max_weight,
        pay_fees,
    );

    if let Ok(result) = &result {
        ensure!(
            result.weight <= max_weight,
            UtxoSelectorError::MaxWeightExceeded
        )
    }

    result
}

/// Find a subset of the OutputGroups that is at least as large as, but as close as possible to, the
/// target amount; solve subset sum.
fn approximate_best_subset(
    rng: &mut impl Rng,
    groups: &[OutputGroup],
    total_lower: Amount,
    target_value: Amount,
    best_solution_selected: &mut [bool],
    best_solution_total: &mut Amount,
    pay_fees: PayFee,
) {
    let mut current_solution_included: Vec<bool> = vec![false; groups.len()];
    // initial best is including all groups
    best_solution_selected.iter_mut().for_each(|elem| *elem = true);
    *best_solution_total = total_lower;

    for _ in 0..1000 {
        // reset selection to all false
        current_solution_included.iter_mut().for_each(|elem| *elem = false);
        let mut total = Amount::ZERO;
        let mut target_reached = false;

        for n_pass in 0..2 {
            for (i, group) in groups.iter().enumerate() {
                //The solver here uses a randomized algorithm,
                //the randomness serves no real security purpose but is just
                //needed to prevent degenerate behavior and it is important
                //that the rng is fast. We do not use a constant random sequence,
                //because there may be some privacy improvement by making
                //the selection random.
                let rand_bool = if n_pass == 0 {
                    rng.gen::<bool>()
                } else {
                    !current_solution_included[i]
                };

                if rand_bool {
                    total = (total + group.get_effective_value(pay_fees))
                        .expect("total sum has been checked to not overflow");
                    current_solution_included[i] = true;

                    if total >= target_value {
                        target_reached = true;

                        if total < *best_solution_total {
                            *best_solution_total = total;
                            best_solution_selected.clone_from_slice(&current_solution_included);
                        }

                        total = (total - group.get_effective_value(pay_fees))
                            .expect("total sum has been checked to not overflow");
                        current_solution_included[i] = false;
                    }
                }
            }

            if target_reached {
                break;
            }
        }
    }
}

/// This is the Branch and Bound Coin Selection algorithm designed by Murch. It searches for an input
/// set that can pay for the spending target and does not exceed the spending target by more than the
/// cost of creating and spending a change output. The algorithm uses a depth-first search on a binary
/// tree. In the binary tree, each node corresponds to the inclusion or the omission of a UTXO. UTXOs
/// are sorted by their effective values and the tree is explored deterministically per the inclusion
/// branch first. At each node, the algorithm checks whether the selection is within the target range.
/// While the selection has not reached the target range, more UTXOs are included. When a selection's
/// value exceeds the target range, the complete subtree deriving from this selection can be omitted.
/// At that point, the last included UTXO is deselected and the corresponding omission branch explored
/// instead. The search ends after the complete tree has been searched or after a limited number of tries.
///
/// The search continues to search for better solutions after one solution has been found. The best
/// solution is chosen by minimizing the waste metric. The waste metric is defined as the cost to
/// spend the current inputs at the given fee rate minus the long term expected cost to spend the
/// inputs, plus the amount by which the selection exceeds the spending target:
///
/// waste = selection_total - target + inputs × (current_fee_rate - long_term_fee_rate)
///
/// The algorithm uses two additional optimizations. A lookahead keeps track of the total value of
/// the unexplored UTXOs. A subtree is not explored if the lookahead indicates that the target range
/// cannot be reached. Further, it is unnecessary to test equivalent combinations. This allows us
/// to skip testing the inclusion of UTXOs that match the effective value and waste of an omitted
/// predecessor.
///
/// The Branch and Bound algorithm is described in detail in Murch's Master Thesis:
/// https://murch.one/wp-content/uploads/2016/11/erhardt2016coinselection.pdf
fn select_coins_bnb(
    mut utxo_pool: Vec<OutputGroup>,
    selection_target: Amount,
    cost_of_change: Amount,
    max_weight: usize,
    pay_fees: PayFee,
) -> Result<SelectionResult, UtxoSelectorError> {
    let mut curr_value = Amount::ZERO;
    let mut curr_selection: Vec<usize> = vec![]; // selected utxo indexes
    let mut curr_selection_weight = 0; // sum of selected utxo weight

    // Calculate curr_available_value
    let mut curr_available_value = utxo_pool
        .iter()
        .map(|utxo| utxo.get_effective_value(pay_fees))
        .sum::<Option<Amount>>()
        .ok_or(UtxoSelectorError::AmountArithmeticError)?;

    if curr_available_value < selection_target {
        return Err(UtxoSelectorError::NotEnoughFunds(
            curr_available_value,
            selection_target,
        ));
    }

    // Sort the utxo_pool
    utxo_pool.sort_by_key(|g| std::cmp::Reverse(g.get_effective_value(pay_fees)));

    let mut curr_waste = SignedAmount::ZERO;
    let mut best_selection = vec![];
    let mut best_waste = SignedAmount::MAX;

    let is_feerate_high = utxo_pool[0].fee > utxo_pool[0].long_term_fee;
    let mut max_tx_weight_exceeded = false;

    // Depth First search loop for choosing the UTXOs
    let mut utxo_pool_index = 0;
    for _ in 0..TOTAL_TRIES {
        // Conditions for starting a backtrack
        let backtrack = if
        // Cannot possibly reach target with the amount remaining in the curr_available_value.
        (curr_value + curr_available_value).expect("total has been check to not overflow") < selection_target
        // Selected value is out of range, go back and try other branch
            || curr_value > (selection_target + cost_of_change).ok_or(UtxoSelectorError::AmountArithmeticError)?
        // Don't select things which we know will be more wasteful if the waste is increasing
            || (curr_waste > best_waste && is_feerate_high)
        {
            true
        }
        // Exceeding weight for standard tx, cannot find more solutions by adding more inputs
        else if curr_selection_weight > max_weight {
            // at least one selection attempt exceeded the max weight
            max_tx_weight_exceeded = true;
            true
        }
        // Selected value is within range
        else if curr_value >= selection_target {
            // This is the excess value which is added to the waste for the below comparison
            let curr_waste = (curr_value - selection_target)
                .expect("curr_value is larger than target")
                .into_signed()
                .and_then(|difference| curr_waste + difference)
                .ok_or(UtxoSelectorError::AmountArithmeticError)?;
            // Adding another UTXO after this check could bring the waste down if the long term fee is higher than the current fee.
            // However we are not going to explore that because this optimization for the waste is only done when we have hit our target
            // value. Adding any more UTXOs will be just burning the UTXO; it will go entirely to fees. Thus we aren't going to
            // explore any more UTXOs to avoid burning money like that.
            if curr_waste <= best_waste {
                best_selection.clone_from(&curr_selection);
                best_waste = curr_waste;
            }
            true
        } else {
            false
        };

        // Backtracking, moving backwards
        if backtrack {
            let curr_last_selected_utxo_index = match curr_selection.pop() {
                // We have walked back to the first utxo and no branch is untraversed. All solutions searched
                None => break,
                Some(idx) => idx,
            };

            // Add omitted UTXOs back to lookahead before traversing the omission branch of last included UTXO.
            let new_available_value = utxo_pool[curr_last_selected_utxo_index + 1..utxo_pool_index]
                .iter()
                .map(|utxo| utxo.get_effective_value(pay_fees))
                .sum::<Option<Amount>>()
                .expect("sum of all UTXOs has already been checked to not overflow");

            curr_available_value =
                (curr_available_value + new_available_value).expect("no overflow");
            // Output was included on previous iterations, try excluding now.
            utxo_pool_index = curr_last_selected_utxo_index;

            let utxo = &utxo_pool[utxo_pool_index];
            curr_value = (curr_value - utxo.get_effective_value(pay_fees)).expect("no underflow");
            curr_waste = utxo
                .fee
                .into_signed()
                .and_then(|fee| {
                    utxo.long_term_fee.into_signed().and_then(|long_term_fee| fee - long_term_fee)
                })
                .and_then(|fee_difference| curr_waste - fee_difference)
                .ok_or(UtxoSelectorError::AmountArithmeticError)?;
            curr_selection_weight -= utxo.weight;
        } else {
            // Moving forwards, continuing down this branch
            let utxo = &utxo_pool[utxo_pool_index];

            // Remove this utxo from the curr_available_value utxo amount
            curr_available_value =
                (curr_available_value - utxo.get_effective_value(pay_fees)).expect("no underflow");

            if curr_selection
                .last()
                // Empty or
                .is_none_or(
                    // The previous index is included and therefore not relevant for exclusion shortcut
                    |idx| utxo_pool_index - 1 == *idx
                )
                // Avoid searching a branch if the previous UTXO has the same value and same waste and was excluded.
                // Since the ratio of fee to long term fee is the same, we only need to check if one of those values match in order to know that the waste is the same.
                || utxo.get_effective_value(pay_fees)
                    != utxo_pool[utxo_pool_index - 1].get_effective_value(pay_fees)
                || utxo.fee != utxo_pool[utxo_pool_index - 1].fee
            {
                // Inclusion branch first (Largest First Exploration)
                curr_selection.push(utxo_pool_index);
                curr_value =
                    (curr_value + utxo.get_effective_value(pay_fees)).expect("no overflow");
                curr_waste = utxo
                    .fee
                    .into_signed()
                    .and_then(|fee| {
                        utxo.long_term_fee
                            .into_signed()
                            .and_then(|long_term_fee| fee - long_term_fee)
                    })
                    .and_then(|fee_difference| curr_waste + fee_difference)
                    .ok_or(UtxoSelectorError::AmountArithmeticError)?;
                curr_selection_weight += utxo.weight;
            }
        }

        utxo_pool_index += 1;
    }

    // Check for solution
    if best_selection.is_empty() {
        return Err(if max_tx_weight_exceeded {
            UtxoSelectorError::MaxWeightExceeded
        } else {
            UtxoSelectorError::NoSolutionFound
        });
    }

    let mut result = SelectionResult::new(selection_target);
    // Set output set
    for i in best_selection {
        result.add_input(&utxo_pool[i], pay_fees)?;
    }

    result.compute_and_set_waste(cost_of_change, cost_of_change, cost_of_change, pay_fees)?;
    assert_eq!(best_waste, result.waste);
    Ok(result)
}

fn select_all_coins(
    utxo_pool: Vec<OutputGroup>,
    selection_target: Amount,
    pay_fees: PayFee,
    cost_of_change: Amount,
) -> Result<SelectionResult, UtxoSelectorError> {
    let mut result = SelectionResult::new(selection_target);
    for utxo in utxo_pool {
        result.add_input(&utxo, pay_fees)?;
    }
    result.compute_and_set_waste(cost_of_change, cost_of_change, cost_of_change, pay_fees)?;

    Ok(result)
}

#[derive(Clone, Copy)]
pub enum CoinSelectionAlgo {
    /// Use all specified inputs.
    UsePreselected,
    /// Choose inputs randomly until the target is satisfied.
    Randomize,
}

pub fn select_coins(
    utxo_pool: Vec<OutputGroup>,
    selection_target: Amount,
    pay_fees: PayFee,
    cost_of_change: Amount,
    coin_selection_algo: CoinSelectionAlgo,
    max_tx_weight: usize,
) -> Result<SelectionResult, UtxoSelectorError> {
    if selection_target == Amount::ZERO {
        return Ok(SelectionResult::new(selection_target));
    }
    ensure!(!utxo_pool.is_empty(), UtxoSelectorError::NoUtxos);

    let total_available_value = utxo_pool
        .iter()
        .map(|utxo| utxo.get_effective_value(pay_fees))
        .sum::<Option<Amount>>()
        .ok_or(UtxoSelectorError::AmountArithmeticError)?;

    ensure!(
        total_available_value >= selection_target,
        UtxoSelectorError::NotEnoughFunds(total_available_value, selection_target,)
    );

    match coin_selection_algo {
        CoinSelectionAlgo::UsePreselected => {
            select_all_coins(utxo_pool, selection_target, pay_fees, cost_of_change)
        }
        CoinSelectionAlgo::Randomize => select_random_coins(
            utxo_pool,
            selection_target,
            cost_of_change,
            pay_fees,
            max_tx_weight,
        ),
    }
}

fn select_random_coins(
    mut utxo_pool: Vec<OutputGroup>,
    selection_target: Amount,
    cost_of_change: Amount,
    pay_fees: PayFee,
    max_weight: usize,
) -> Result<SelectionResult, UtxoSelectorError> {
    let mut rng = make_pseudo_rng();

    let mut results = vec![];
    let mut errors = vec![];

    match select_coins_srd(
        &utxo_pool,
        selection_target,
        &mut rng,
        cost_of_change,
        max_weight,
        pay_fees,
    ) {
        Ok(mut result) => {
            result.compute_and_set_waste(
                cost_of_change,
                cost_of_change,
                cost_of_change,
                pay_fees,
            )?;
            results.push(result)
        }
        Err(error) => errors.push(error),
    };

    match knapsack_solver(
        &mut utxo_pool,
        selection_target,
        cost_of_change,
        &mut rng,
        max_weight,
        pay_fees,
    ) {
        Ok(mut result) => {
            result.compute_and_set_waste(
                cost_of_change,
                cost_of_change,
                cost_of_change,
                pay_fees,
            )?;
            results.push(result)
        }
        Err(error) => errors.push(error),
    };

    match select_coins_bnb(
        utxo_pool,
        selection_target,
        cost_of_change,
        max_weight,
        pay_fees,
    ) {
        Ok(result) => results.push(result),
        Err(error) => errors.push(error),
    };

    results
        .into_iter()
        .min_by_key(|res| res.waste)
        .ok_or_else(|| errors.pop().unwrap_or(UtxoSelectorError::NoSolutionFound))
}

#[cfg(test)]
mod tests;
