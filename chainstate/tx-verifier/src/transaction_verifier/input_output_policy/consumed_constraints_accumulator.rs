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

use std::{collections::BTreeMap, num::NonZeroU64};

use common::{
    chain::ChainConfig,
    primitives::{Amount, BlockHeight},
};

use crate::{transaction_verifier::CoinOrTokenId, Fee};

use super::IOPolicyError;

#[derive(Debug, PartialEq, Eq)]
pub struct ConsumedConstrainedValueAccumulator {
    unconstrained_value: BTreeMap<CoinOrTokenId, Amount>,
    timelock_constrained: BTreeMap<NonZeroU64, Amount>,
}

impl ConsumedConstrainedValueAccumulator {
    pub fn new() -> Self {
        Self {
            unconstrained_value: Default::default(),
            timelock_constrained: Default::default(),
        }
    }

    pub(super) fn from_values(
        unconstrained_value: BTreeMap<CoinOrTokenId, Amount>,
        timelock_constrained: BTreeMap<NonZeroU64, Amount>,
    ) -> Self {
        Self {
            unconstrained_value,
            timelock_constrained,
        }
    }

    pub fn combine(
        &mut self,
        other: ConsumedConstrainedValueAccumulator,
    ) -> Result<(), IOPolicyError> {
        merge_amount_maps(&mut self.unconstrained_value, other.unconstrained_value)?;
        merge_amount_maps(&mut self.timelock_constrained, other.timelock_constrained)?;

        Ok(())
    }

    /// Return accumulated coins that are left
    pub fn calculate_fee(
        self,
        chain_config: &ChainConfig,
        block_height: BlockHeight,
    ) -> Result<Fee, IOPolicyError> {
        let unconstrained_change = self
            .unconstrained_value
            .get(&CoinOrTokenId::Coin)
            .cloned()
            .unwrap_or(Amount::ZERO);

        let maturity_distance = chain_config.staking_pool_spend_maturity_block_count(block_height);

        let timelocked_change = self
            .timelock_constrained
            .into_iter()
            .filter_map(|(lock, amount)| {
                (lock.get() <= maturity_distance.to_int()).then_some(amount)
            })
            .sum::<Option<Amount>>()
            .ok_or(IOPolicyError::CoinOrTokenOverflow(CoinOrTokenId::Coin))?;

        let fee = (unconstrained_change + timelocked_change)
            .ok_or(IOPolicyError::CoinOrTokenOverflow(CoinOrTokenId::Coin))?;

        Ok(Fee(fee))
    }
}

fn merge_amount_maps<K: Ord>(
    left: &mut BTreeMap<K, Amount>,
    right: BTreeMap<K, Amount>,
) -> Result<(), IOPolicyError> {
    for (key, value) in right {
        match left.get(&key) {
            Some(existing_value) => {
                let new_value = (*existing_value + value).ok_or(IOPolicyError::AmountOverflow)?;
                left.insert(key, new_value);
            }
            None => {
                left.insert(key, value);
            }
        }
    }

    Ok(())
}
