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

use accounting::DataDeltaUndo;
use common::{
    chain::{DelegationId, Destination, PoolId},
    primitives::Amount,
};
use serialization::{Decode, Encode};
use strum::EnumCount;

use crate::error::Error;

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct CreatePoolUndo {
    pub(crate) pool_id: PoolId,
    pub(crate) pledge_amount: Amount,
    pub(crate) data_undo: DataDeltaUndo<PoolData>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct CreateDelegationIdUndo {
    pub(crate) delegation_id: DelegationId,
    pub(crate) data_undo: DataDeltaUndo<DelegationData>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct DeleteDelegationIdUndo {
    pub(crate) delegation_id: DelegationId,
    pub(crate) data_undo: DataDeltaUndo<DelegationData>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct DecommissionPoolUndo {
    pub(crate) pool_id: PoolId,
    pub(crate) pool_balance: Amount,
    pub(crate) data_undo: DataDeltaUndo<PoolData>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct DelegateStakingUndo {
    pub(crate) delegation_target: DelegationId,
    pub(crate) amount_to_delegate: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct SpendFromShareUndo {
    pub(crate) delegation_id: DelegationId,
    pub(crate) amount: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct IncreaseStakerRewardsUndo {
    pub(crate) pool_id: PoolId,
    pub(crate) amount_added: Amount,
    pub(crate) data_undo: DataDeltaUndo<PoolData>,
}

#[must_use]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, EnumCount)]
pub enum PoSAccountingUndo {
    #[codec(index = 0)]
    CreatePool(CreatePoolUndo),
    #[codec(index = 1)]
    DecommissionPool(DecommissionPoolUndo),
    #[codec(index = 2)]
    CreateDelegationId(CreateDelegationIdUndo),
    #[codec(index = 3)]
    DeleteDelegationId(DeleteDelegationIdUndo),
    #[codec(index = 4)]
    DelegateStaking(DelegateStakingUndo),
    #[codec(index = 5)]
    SpendFromShare(SpendFromShareUndo),
    #[codec(index = 6)]
    IncreaseStakerRewards(IncreaseStakerRewardsUndo),
}

use super::{delegation::DelegationData, pool_data::PoolData};

pub trait PoSAccountingOperations<U> {
    fn create_pool(&mut self, pool_id: PoolId, pool_data: PoolData) -> Result<U, Error>;

    fn decommission_pool(&mut self, pool_id: PoolId) -> Result<U, Error>;

    fn increase_staker_rewards(
        &mut self,
        pool_id: PoolId,
        amount_to_add: Amount,
    ) -> Result<U, Error>;

    fn create_delegation_id(
        &mut self,
        target_pool: PoolId,
        delegation_id: DelegationId,
        spend_key: Destination,
    ) -> Result<U, Error>;

    fn delete_delegation_id(&mut self, delegation_id: DelegationId) -> Result<U, Error>;

    fn delegate_staking(
        &mut self,
        delegation_target: DelegationId,
        amount_to_delegate: Amount,
    ) -> Result<U, Error>;

    fn spend_share_from_delegation_id(
        &mut self,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> Result<U, Error>;

    fn undo(&mut self, undo_data: U) -> Result<(), Error>;
}
