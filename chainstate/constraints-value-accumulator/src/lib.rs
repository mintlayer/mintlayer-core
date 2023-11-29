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

use common::primitives::Amount;

mod accumulated_fee;
mod constraints_accumulator;
mod error;

fn insert_or_increase<K: Ord>(
    collection: &mut BTreeMap<K, Amount>,
    key: K,
    amount: Amount,
) -> Result<(), crate::Error> {
    let value = collection.entry(key).or_insert(Amount::ZERO);
    *value = (*value + amount).ok_or(crate::Error::AmountOverflow)?;

    Ok(())
}

pub use crate::{
    accumulated_fee::AccumulatedFee, constraints_accumulator::ConstrainedValueAccumulator,
    error::Error,
};

#[cfg(test)]
mod tests;
