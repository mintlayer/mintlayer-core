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
    primitives::{Amount, BlockHeight, CoinOrTokenId, Fee},
};

use super::Error;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AccumulatedFee {
    unconstrained_value: BTreeMap<CoinOrTokenId, Amount>,
    timelock_constrained: BTreeMap<NonZeroU64, Amount>,
}

impl AccumulatedFee {
    pub fn new() -> Self {
        Self {
            unconstrained_value: Default::default(),
            timelock_constrained: Default::default(),
        }
    }

    pub(super) fn from_data(
        unconstrained_value: BTreeMap<CoinOrTokenId, Amount>,
        timelock_constrained: BTreeMap<NonZeroU64, Amount>,
    ) -> Self {
        Self {
            unconstrained_value,
            timelock_constrained,
        }
    }

    pub fn combine(self, other: Self) -> Result<Self, Error> {
        let unconstrained_value =
            merge_amount_maps(self.unconstrained_value, other.unconstrained_value)?;
        let timelock_constrained =
            merge_amount_maps(self.timelock_constrained, other.timelock_constrained)?;

        Ok(Self {
            unconstrained_value,
            timelock_constrained,
        })
    }

    /// Map/project the accumulator into an object that represents the accumulated block fees.
    /// We call this projection because the result of this projection is a subgroup of the `ConstrainedValueAccumulator` group
    /// under the 'accumulation' operation, where we can accumulate fees as well in the subgroup.
    pub fn map_into_block_fees(
        self,
        chain_config: &ChainConfig,
        block_height: BlockHeight,
    ) -> Result<Fee, Error> {
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
            .ok_or(Error::CoinOrTokenOverflow(CoinOrTokenId::Coin))?;

        let fee = (unconstrained_change + timelocked_change)
            .ok_or(Error::CoinOrTokenOverflow(CoinOrTokenId::Coin))?;

        Ok(Fee(fee))
    }
}

fn merge_amount_maps<K: Ord>(
    mut left: BTreeMap<K, Amount>,
    right: BTreeMap<K, Amount>,
) -> Result<BTreeMap<K, Amount>, Error> {
    right
        .into_iter()
        .try_for_each(|(key, value)| super::insert_or_increase(&mut left, key, value))?;
    Ok(left)
}
