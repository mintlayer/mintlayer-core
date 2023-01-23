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

//! A mock version of the blockchain storage.

use std::collections::BTreeMap;

use common::primitives::Amount;
use pos_accounting::{
    DelegationData, DelegationId, PoSAccountingStorageRead, PoSAccountingStorageWrite, PoolData,
    PoolId,
};

use super::{MockStore, MockStoreTxRo, MockStoreTxRw};

pub trait PoSAccountingStorageReadTip {
    fn get_pool_balance_tip(&self, pool_id: PoolId) -> crate::Result<Option<Amount>>;
    fn get_pool_data_tip(&self, pool_id: PoolId) -> crate::Result<Option<PoolData>>;
    fn get_delegation_balance_tip(
        &self,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<Amount>>;
    fn get_delegation_data_tip(
        &self,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<DelegationData>>;
    fn get_pool_delegations_shares_tip(
        &self,
        pool_id: PoolId,
    ) -> crate::Result<Option<BTreeMap<DelegationId, Amount>>>;
    fn get_pool_delegation_share_tip(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<Amount>>;
}

pub trait PoSAccountingStorageReadSealed {
    fn get_pool_balance_sealed(&self, pool_id: PoolId) -> crate::Result<Option<Amount>>;
    fn get_pool_data_sealed(&self, pool_id: PoolId) -> crate::Result<Option<PoolData>>;
    fn get_delegation_balance_sealed(
        &self,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<Amount>>;
    fn get_delegation_data_sealed(
        &self,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<DelegationData>>;
    fn get_pool_delegations_shares_sealed(
        &self,
        pool_id: PoolId,
    ) -> crate::Result<Option<BTreeMap<DelegationId, Amount>>>;
    fn get_pool_delegation_share_sealed(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<Amount>>;
}

pub trait PoSAccountingStorageWriteTip: PoSAccountingStorageReadTip {
    fn set_pool_balance_tip(&mut self, pool_id: PoolId, amount: Amount) -> crate::Result<()>;
    fn del_pool_balance_tip(&mut self, pool_id: PoolId) -> crate::Result<()>;

    fn set_pool_data_tip(&mut self, pool_id: PoolId, pool_data: &PoolData) -> crate::Result<()>;
    fn del_pool_data_tip(&mut self, pool_id: PoolId) -> crate::Result<()>;

    fn set_delegation_balance_tip(
        &mut self,
        delegation_target: DelegationId,
        amount: Amount,
    ) -> crate::Result<()>;
    fn del_delegation_balance_tip(&mut self, delegation_target: DelegationId) -> crate::Result<()>;

    fn set_delegation_data_tip(
        &mut self,
        delegation_id: DelegationId,
        delegation_data: &DelegationData,
    ) -> crate::Result<()>;
    fn del_delegation_data_tip(&mut self, delegation_id: DelegationId) -> crate::Result<()>;

    fn set_pool_delegation_share_tip(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> crate::Result<()>;
    fn del_pool_delegation_share_tip(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> crate::Result<()>;
}

pub trait PoSAccountingStorageWriteSealed: PoSAccountingStorageReadSealed {
    fn set_pool_balance_sealed(&mut self, pool_id: PoolId, amount: Amount) -> crate::Result<()>;
    fn del_pool_balance_sealed(&mut self, pool_id: PoolId) -> crate::Result<()>;

    fn set_pool_data_sealed(&mut self, pool_id: PoolId, pool_data: &PoolData) -> crate::Result<()>;
    fn del_pool_data_sealed(&mut self, pool_id: PoolId) -> crate::Result<()>;

    fn set_delegation_balance_sealed(
        &mut self,
        delegation_target: DelegationId,
        amount: Amount,
    ) -> crate::Result<()>;
    fn del_delegation_balance_sealed(
        &mut self,
        delegation_target: DelegationId,
    ) -> crate::Result<()>;

    fn set_delegation_data_sealed(
        &mut self,
        delegation_id: DelegationId,
        delegation_data: &DelegationData,
    ) -> crate::Result<()>;
    fn del_delegation_data_sealed(&mut self, delegation_id: DelegationId) -> crate::Result<()>;

    fn set_pool_delegation_share_sealed(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> crate::Result<()>;
    fn del_pool_delegation_share_sealed(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> crate::Result<()>;
}

macro_rules! impl_sealed_read_ops {
    ($StoreType:ident) => {
        impl PoSAccountingStorageRead<crate::SealedStorageTag> for $StoreType {
            fn get_pool_balance(&self, pool_id: PoolId) -> crate::Result<Option<Amount>> {
                self.get_pool_balance_sealed(pool_id)
            }
            fn get_pool_data(&self, pool_id: PoolId) -> crate::Result<Option<PoolData>> {
                self.get_pool_data_sealed(pool_id)
            }
            fn get_delegation_balance(
                &self,
                delegation_target: DelegationId,
            ) -> crate::Result<Option<Amount>> {
                self.get_delegation_balance_sealed(delegation_target)
            }
            fn get_delegation_data(
                &self,
                delegation_id: DelegationId,
            ) -> crate::Result<Option<DelegationData>> {
                self.get_delegation_data_sealed(delegation_id)
            }
            fn get_pool_delegation_share(
                &self,
                pool_id: PoolId,
                delegation_id: DelegationId,
            ) -> crate::Result<Option<Amount>> {
                self.get_pool_delegation_share_sealed(pool_id, delegation_id)
            }
            fn get_pool_delegations_shares(
                &self,
                pool_id: PoolId,
            ) -> crate::Result<Option<BTreeMap<DelegationId, Amount>>> {
                self.get_pool_delegations_shares_sealed(pool_id)
            }
        }
    };
}

macro_rules! impl_tip_read_ops {
    ($StoreType:ident) => {
        impl PoSAccountingStorageRead<crate::TipStorageTag> for $StoreType {
            fn get_pool_balance(&self, pool_id: PoolId) -> crate::Result<Option<Amount>> {
                self.get_pool_balance_tip(pool_id)
            }
            fn get_pool_data(&self, pool_id: PoolId) -> crate::Result<Option<PoolData>> {
                self.get_pool_data_tip(pool_id)
            }
            fn get_delegation_balance(
                &self,
                delegation_target: DelegationId,
            ) -> crate::Result<Option<Amount>> {
                self.get_delegation_balance_tip(delegation_target)
            }
            fn get_delegation_data(
                &self,
                delegation_id: DelegationId,
            ) -> crate::Result<Option<DelegationData>> {
                self.get_delegation_data_tip(delegation_id)
            }
            fn get_pool_delegation_share(
                &self,
                pool_id: PoolId,
                delegation_id: DelegationId,
            ) -> crate::Result<Option<Amount>> {
                self.get_pool_delegation_share_tip(pool_id, delegation_id)
            }
            fn get_pool_delegations_shares(
                &self,
                pool_id: PoolId,
            ) -> crate::Result<Option<BTreeMap<DelegationId, Amount>>> {
                self.get_pool_delegations_shares_tip(pool_id)
            }
        }
    };
}

macro_rules! impl_sealed_write_ops {
    ($StoreType:ident) => {
        impl PoSAccountingStorageWrite<crate::SealedStorageTag> for $StoreType {
            fn set_pool_balance(&mut self, pool_id: PoolId, amount: Amount) -> crate::Result<()> {
                self.set_pool_balance_sealed(pool_id, amount)
            }
            fn del_pool_balance(&mut self, pool_id: PoolId) -> crate::Result<()> {
                self.del_pool_balance_sealed(pool_id)
            }

            fn set_pool_data(
                &mut self,
                pool_id: PoolId,
                pool_data: &PoolData,
            ) -> crate::Result<()> {
                self.set_pool_data_sealed(pool_id, pool_data)
            }
            fn del_pool_data(&mut self, pool_id: PoolId) -> crate::Result<()> {
                self.del_pool_data_sealed(pool_id)
            }

            fn set_delegation_balance(
                &mut self,
                delegation_target: DelegationId,
                amount: Amount,
            ) -> crate::Result<()> {
                self.set_delegation_balance_sealed(delegation_target, amount)
            }

            fn del_delegation_balance(
                &mut self,
                delegation_target: DelegationId,
            ) -> crate::Result<()> {
                self.del_delegation_balance_sealed(delegation_target)
            }

            fn set_delegation_data(
                &mut self,
                delegation_id: DelegationId,
                delegation_data: &DelegationData,
            ) -> crate::Result<()> {
                self.set_delegation_data_sealed(delegation_id, delegation_data)
            }

            fn del_delegation_data(&mut self, delegation_id: DelegationId) -> crate::Result<()> {
                self.del_delegation_data_sealed(delegation_id)
            }

            fn set_pool_delegation_share(
                &mut self,
                pool_id: PoolId,
                delegation_id: DelegationId,
                amount: Amount,
            ) -> crate::Result<()> {
                self.set_pool_delegation_share_sealed(pool_id, delegation_id, amount)
            }

            fn del_pool_delegation_share(
                &mut self,
                pool_id: PoolId,
                delegation_id: DelegationId,
            ) -> crate::Result<()> {
                self.del_pool_delegation_share_sealed(pool_id, delegation_id)
            }
        }
    };
}

macro_rules! impl_tip_write_ops {
    ($StoreType:ident) => {
        impl PoSAccountingStorageWrite<crate::TipStorageTag> for $StoreType {
            fn set_pool_balance(&mut self, pool_id: PoolId, amount: Amount) -> crate::Result<()> {
                self.set_pool_balance_tip(pool_id, amount)
            }
            fn del_pool_balance(&mut self, pool_id: PoolId) -> crate::Result<()> {
                self.del_pool_balance_tip(pool_id)
            }

            fn set_pool_data(
                &mut self,
                pool_id: PoolId,
                pool_data: &PoolData,
            ) -> crate::Result<()> {
                self.set_pool_data_tip(pool_id, pool_data)
            }
            fn del_pool_data(&mut self, pool_id: PoolId) -> crate::Result<()> {
                self.del_pool_data_tip(pool_id)
            }

            fn set_delegation_balance(
                &mut self,
                delegation_target: DelegationId,
                amount: Amount,
            ) -> crate::Result<()> {
                self.set_delegation_balance_tip(delegation_target, amount)
            }

            fn del_delegation_balance(
                &mut self,
                delegation_target: DelegationId,
            ) -> crate::Result<()> {
                self.del_delegation_balance_tip(delegation_target)
            }

            fn set_delegation_data(
                &mut self,
                delegation_id: DelegationId,
                delegation_data: &DelegationData,
            ) -> crate::Result<()> {
                self.set_delegation_data_tip(delegation_id, delegation_data)
            }

            fn del_delegation_data(&mut self, delegation_id: DelegationId) -> crate::Result<()> {
                self.del_delegation_data_tip(delegation_id)
            }

            fn set_pool_delegation_share(
                &mut self,
                pool_id: PoolId,
                delegation_id: DelegationId,
                amount: Amount,
            ) -> crate::Result<()> {
                self.set_pool_delegation_share_tip(pool_id, delegation_id, amount)
            }

            fn del_pool_delegation_share(
                &mut self,
                pool_id: PoolId,
                delegation_id: DelegationId,
            ) -> crate::Result<()> {
                self.del_pool_delegation_share_tip(pool_id, delegation_id)
            }
        }
    };
}

impl_tip_read_ops!(MockStore);
impl_sealed_read_ops!(MockStore);
impl_tip_write_ops!(MockStore);
impl_sealed_write_ops!(MockStore);

impl_tip_read_ops!(MockStoreTxRo);
impl_sealed_read_ops!(MockStoreTxRo);

impl_tip_read_ops!(MockStoreTxRw);
impl_sealed_read_ops!(MockStoreTxRw);
impl_tip_write_ops!(MockStoreTxRw);
impl_sealed_write_ops!(MockStoreTxRw);
