// Copyright (c) 2022 RBB S.r.l
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

use accounting::DeltaDataUndoCollection;
use common::primitives::{signed_amount::SignedAmount, Amount, H256};

use crate::{error::Error, DelegationId, PoolId};

use self::data::PoSAccountingDeltaData;

use super::{delegation::DelegationData, pool_data::PoolData, view::PoSAccountingView};

pub mod data;
pub mod operator_impls;
mod view_impl;

enum PoSAccountingViewCow<'a, P> {
    Borrowed(&'a P),
    Owned(P),
}

impl<'a, P: PoSAccountingView> PoSAccountingViewCow<'a, P> {
    fn as_bounded_ref(&self) -> &P {
        match self {
            PoSAccountingViewCow::Borrowed(r) => r,
            PoSAccountingViewCow::Owned(o) => o,
        }
    }
}

pub struct PoSAccountingDelta<'a, P> {
    parent: PoSAccountingViewCow<'a, P>,
    data: PoSAccountingDeltaData,
}

/// All the operations we have to do with the accounting state to undo a delta
pub struct DeltaMergeUndo {
    pool_data_undo: DeltaDataUndoCollection<PoolId, PoolData>,
    delegation_data_undo: DeltaDataUndoCollection<DelegationId, DelegationData>,
}

impl<'a, P: PoSAccountingView> PoSAccountingDelta<'a, P> {
    pub fn from_borrowed_parent(parent: &'a P) -> Self {
        Self {
            parent: PoSAccountingViewCow::Borrowed(parent),
            data: PoSAccountingDeltaData::new(),
        }
    }

    pub fn from_owned_parent(parent: P) -> Self {
        Self {
            parent: PoSAccountingViewCow::Owned(parent),
            data: PoSAccountingDeltaData::new(),
        }
    }

    #[cfg(test)]
    pub fn from_data(parent: &'a P, data: PoSAccountingDeltaData) -> Self {
        Self {
            parent: PoSAccountingViewCow::Borrowed(parent),
            data,
        }
    }

    pub fn consume(self) -> PoSAccountingDeltaData {
        self.data
    }

    pub fn data(&self) -> &PoSAccountingDeltaData {
        &self.data
    }

    fn get_cached_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Option<BTreeMap<DelegationId, SignedAmount>> {
        let range_start = (pool_id, DelegationId::new(H256::zero()));
        let range_end = (pool_id, DelegationId::new(H256::repeat_byte(0xFF)));
        let range = self.data.pool_delegation_shares.data().range(range_start..=range_end);
        let result = range.map(|((_, del_id), v)| (*del_id, *v)).collect::<BTreeMap<_, _>>();
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    pub fn undo_delta_merge(
        &mut self,
        already_merged: PoSAccountingDeltaData,
        undo_data: DeltaMergeUndo,
    ) -> Result<(), Error> {
        self.data.pool_balances.undo_merge_delta_amounts(already_merged.pool_balances)?;

        self.data
            .pool_delegation_shares
            .undo_merge_delta_amounts(already_merged.pool_delegation_shares)?;

        self.data
            .delegation_balances
            .undo_merge_delta_amounts(already_merged.delegation_balances)?;

        self.data.pool_data.undo_merge_delta_data(undo_data.pool_data_undo)?;

        self.data
            .delegation_data
            .undo_merge_delta_data(undo_data.delegation_data_undo)?;

        Ok(())
    }

    pub fn merge_with_delta(
        &mut self,
        other: PoSAccountingDeltaData,
    ) -> Result<DeltaMergeUndo, Error> {
        self.data.pool_balances.merge_delta_amounts(other.pool_balances)?;

        self.data
            .pool_delegation_shares
            .merge_delta_amounts(other.pool_delegation_shares)?;

        self.data.delegation_balances.merge_delta_amounts(other.delegation_balances)?;

        let pool_data_undo = self.data.pool_data.merge_delta_data(other.pool_data)?;

        let delegation_data_undo =
            self.data.delegation_data.merge_delta_data(other.delegation_data)?;

        Ok(DeltaMergeUndo {
            pool_data_undo,
            delegation_data_undo,
        })
    }

    fn add_to_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
        amount_to_delegate: Amount,
    ) -> Result<(), Error> {
        self.data
            .delegation_balances
            .add_unsigned(delegation_target, amount_to_delegate)
            .map_err(Error::AccountingError)
    }

    fn sub_from_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
        amount_to_delegate: Amount,
    ) -> Result<(), Error> {
        self.data
            .delegation_balances
            .sub_unsigned(delegation_target, amount_to_delegate)
            .map_err(Error::AccountingError)
    }

    fn add_balance_to_pool(&mut self, pool_id: PoolId, amount_to_add: Amount) -> Result<(), Error> {
        self.data
            .pool_balances
            .add_unsigned(pool_id, amount_to_add)
            .map_err(Error::AccountingError)
    }

    fn sub_balance_from_pool(
        &mut self,
        pool_id: PoolId,
        amount_to_add: Amount,
    ) -> Result<(), Error> {
        self.data
            .pool_balances
            .sub_unsigned(pool_id, amount_to_add)
            .map_err(Error::AccountingError)
    }

    fn add_delegation_to_pool_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
        amount_to_add: Amount,
    ) -> Result<(), Error> {
        self.data
            .pool_delegation_shares
            .add_unsigned((pool_id, delegation_id), amount_to_add)
            .map_err(Error::AccountingError)
    }

    fn sub_delegation_from_pool_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
        amount_to_add: Amount,
    ) -> Result<(), Error> {
        self.data
            .pool_delegation_shares
            .sub_unsigned((pool_id, delegation_id), amount_to_add)
            .map_err(Error::AccountingError)
    }
}

// TODO: this is used in both operator and view impls. Find an appropriate place for it.
fn sum_maps<K: Ord + Copy>(
    mut m1: BTreeMap<K, Amount>,
    m2: BTreeMap<K, SignedAmount>,
) -> Result<BTreeMap<K, Amount>, Error> {
    for (k, v) in m2 {
        let base_value = match m1.get(&k) {
            Some(pv) => *pv,
            None => Amount::from_atoms(0),
        };
        let base_amount = base_value.into_signed().ok_or(Error::AccountingError(
            accounting::Error::ArithmeticErrorToUnsignedFailed,
        ))?;
        let new_amount = (base_amount + v).ok_or(Error::AccountingError(
            accounting::Error::ArithmeticErrorSumToSignedFailed,
        ))?;
        let new_amount = new_amount.into_unsigned().ok_or(Error::AccountingError(
            accounting::Error::ArithmeticErrorToUnsignedFailed,
        ))?;
        m1.insert(k, new_amount);
    }
    Ok(m1)
}
