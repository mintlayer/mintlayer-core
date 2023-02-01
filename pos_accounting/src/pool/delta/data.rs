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

use accounting::{DeltaAmountCollection, DeltaDataCollection};

use crate::{
    pool::{delegation::DelegationData, pool_data::PoolData},
    DelegationId, DeltaMergeUndo, Error, PoolId,
};

use serialization::{Decode, Encode};

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq)]
pub struct PoSAccountingDeltaData {
    pub pool_data: DeltaDataCollection<PoolId, PoolData>,
    pub pool_balances: DeltaAmountCollection<PoolId>,
    pub pool_delegation_shares: DeltaAmountCollection<(PoolId, DelegationId)>,
    pub delegation_balances: DeltaAmountCollection<DelegationId>,
    pub delegation_data: DeltaDataCollection<DelegationId, DelegationData>,
}

impl PoSAccountingDeltaData {
    pub fn new() -> Self {
        Self {
            pool_data: DeltaDataCollection::new(),
            pool_balances: DeltaAmountCollection::new(),
            pool_delegation_shares: DeltaAmountCollection::new(),
            delegation_balances: DeltaAmountCollection::new(),
            delegation_data: DeltaDataCollection::new(),
        }
    }

    pub fn merge_with_delta(
        &mut self,
        other: PoSAccountingDeltaData,
    ) -> Result<DeltaMergeUndo, Error> {
        let pool_balances_undo = other.pool_balances.clone();
        self.pool_balances.merge_delta_amounts(other.pool_balances)?;

        let pool_delegation_shares_undo = other.pool_delegation_shares.clone();
        self.pool_delegation_shares.merge_delta_amounts(other.pool_delegation_shares)?;

        let delegation_balances_undo = other.delegation_balances.clone();
        self.delegation_balances.merge_delta_amounts(other.delegation_balances)?;

        let pool_data_undo = self.pool_data.merge_delta_data(other.pool_data)?;
        let delegation_data_undo = self.delegation_data.merge_delta_data(other.delegation_data)?;

        Ok(DeltaMergeUndo {
            pool_data_undo,
            delegation_data_undo,
            pool_balances_undo,
            delegation_balances_undo,
            pool_delegation_shares_undo,
        })
    }

    pub fn undo_delta_merge(&mut self, undo_data: DeltaMergeUndo) -> Result<(), Error> {
        self.pool_balances.undo_merge_delta_amounts(undo_data.pool_balances_undo)?;

        self.pool_delegation_shares
            .undo_merge_delta_amounts(undo_data.pool_delegation_shares_undo)?;

        self.delegation_balances
            .undo_merge_delta_amounts(undo_data.delegation_balances_undo)?;

        self.pool_data.undo_merge_delta_data(undo_data.pool_data_undo)?;

        self.delegation_data.undo_merge_delta_data(undo_data.delegation_data_undo)?;

        Ok(())
    }
}

impl Default for PoSAccountingDeltaData {
    fn default() -> Self {
        Self::new()
    }
}
