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
use common::{chain::OutPoint, primitives::Amount};
use crypto::key::PublicKey;
use serialization::{Decode, Encode};

use crate::{error::Error, DelegationId, PoolId};

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) enum PoolDataUndo {
    Data(Box<PoolData>),
    DataDelta(Box<(Amount, DataDeltaUndo<PoolData>)>),
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) enum DelegationDataUndo {
    Data(Box<DelegationData>),
    DataDelta(Box<DataDeltaUndo<DelegationData>>),
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct CreatePoolUndo {
    pub(crate) pool_id: PoolId,
    pub(crate) data_undo: PoolDataUndo,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct CreateDelegationIdUndo {
    pub(crate) delegation_id: DelegationId,
    pub(crate) data_undo: DelegationDataUndo,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct DecommissionPoolUndo {
    pub(crate) pool_id: PoolId,
    pub(crate) data_undo: PoolDataUndo,
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
pub enum PoSAccountingUndo {
    CreatePool(CreatePoolUndo),
    DecommissionPool(DecommissionPoolUndo),
    CreateDelegationId(CreateDelegationIdUndo),
    DelegateStaking(DelegateStakingUndo),
    SpendFromShare(SpendFromShareUndo),
}

use super::{delegation::DelegationData, pool_data::PoolData};

pub trait PoSAccountingOperations {
    fn create_pool(
        &mut self,
        input0_outpoint: &OutPoint,
        pledge_amount: Amount,
        decommission_key: PublicKey,
    ) -> Result<(PoolId, PoSAccountingUndo), Error>;

    fn decommission_pool(&mut self, pool_id: PoolId) -> Result<PoSAccountingUndo, Error>;

    fn create_delegation_id(
        &mut self,
        target_pool: PoolId,
        spend_key: PublicKey,
        input0_outpoint: &OutPoint,
    ) -> Result<(DelegationId, PoSAccountingUndo), Error>;

    fn delegate_staking(
        &mut self,
        delegation_target: DelegationId,
        amount_to_delegate: Amount,
    ) -> Result<PoSAccountingUndo, Error>;

    fn spend_share_from_delegation_id(
        &mut self,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> Result<PoSAccountingUndo, Error>;

    fn undo(&mut self, undo_data: PoSAccountingUndo) -> Result<(), Error>;
}
