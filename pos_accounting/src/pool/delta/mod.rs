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

use accounting::{DeltaAmountCollection, DeltaDataUndoCollection};
use common::primitives::{signed_amount::SignedAmount, Amount, H256};
use serialization::{Decode, Encode};

use crate::{error::Error, DelegationId, PoolId};

use self::data::PoSAccountingDeltaData;

use super::{delegation::DelegationData, pool_data::PoolData, view::PoSAccountingView};

pub mod data;
pub mod operator_impls;
mod view_impl;

pub struct PoSAccountingDelta<P> {
    parent: P,
    data: PoSAccountingDeltaData,
}

/// All the operations we have to do with the accounting state to undo a delta
#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq)]
pub struct DeltaMergeUndo {
    pool_data_undo: DeltaDataUndoCollection<PoolId, PoolData>,
    delegation_data_undo: DeltaDataUndoCollection<DelegationId, DelegationData>,
    pool_balances_undo: DeltaAmountCollection<PoolId>,
    pool_delegation_shares_undo: DeltaAmountCollection<(PoolId, DelegationId)>,
    delegation_balances_undo: DeltaAmountCollection<DelegationId>,
}

impl<P: PoSAccountingView> PoSAccountingDelta<P> {
    pub fn new(parent: P) -> Self {
        Self {
            parent,
            data: PoSAccountingDeltaData::new(),
        }
    }

    #[cfg(test)]
    pub fn from_data(parent: P, data: PoSAccountingDeltaData) -> Self {
        Self { parent, data }
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

    pub fn merge_with_delta(
        &mut self,
        other: PoSAccountingDeltaData,
    ) -> Result<DeltaMergeUndo, Error> {
        self.data.merge_with_delta(other)
    }

    pub fn undo_delta_merge(&mut self, undo_data: DeltaMergeUndo) -> Result<(), Error> {
        self.data.undo_delta_merge(undo_data)
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
