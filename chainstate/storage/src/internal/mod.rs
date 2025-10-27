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

mod store_tx;

#[cfg(any(test, feature = "expensive-reads"))]
mod expensive;

use std::collections::BTreeMap;

use chainstate_types::{SealedStorageTag, TipStorageTag};
use common::{
    chain::{ChainConfig, DelegationId, PoolId},
    primitives::Amount,
};
use pos_accounting::{
    DelegationData, PoSAccountingStorageRead, PoSAccountingStorageWrite, PoolData,
};
use utils::log_error;

use crate::{
    schema::Schema, BlockchainStorage, BlockchainStorageRead, BlockchainStorageWrite,
    TransactionRw, Transactional,
};

pub use store_tx::{StoreTxRo, StoreTxRw};

mod version;
pub use version::ChainstateStorageVersion;

/// Store for blockchain data, parametrized over the backend B
pub struct Store<B: storage::SharedBackend>(storage::Storage<B, Schema>);

impl<B: storage::SharedBackend> Store<B> {
    /// Create a new chainstate storage
    #[log_error]
    pub fn new(backend: B, chain_config: &ChainConfig) -> crate::Result<Self> {
        let storage = Self::from_backend(backend)?;

        // Set defaults if missing
        let mut db_tx = storage.transaction_rw(None)?;

        if db_tx.get_storage_version()?.is_none() {
            db_tx.set_storage_version(ChainstateStorageVersion::CURRENT)?;
        }

        if db_tx.get_magic_bytes()?.is_none() {
            db_tx.set_magic_bytes(chain_config.magic_bytes())?;
        }

        if db_tx.get_chain_type()?.is_none() {
            db_tx.set_chain_type(chain_config.chain_type().name())?;
        }

        db_tx.commit()?;

        Ok(storage)
    }

    #[log_error]
    pub fn from_backend(backend: B) -> crate::Result<Self> {
        let storage = Self(storage::Storage::new(backend).map_err(crate::Error::from)?);
        Ok(storage)
    }
}

impl<B: Default + storage::SharedBackend> Store<B> {
    /// Create a default storage (mostly for testing, may want to remove this later)
    #[log_error]
    pub fn new_empty() -> crate::Result<Self> {
        Self::from_backend(B::default())
    }
}

impl<B: storage::SharedBackend> Clone for Store<B>
where
    storage::Storage<B, Schema>: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<'tx, B: storage::SharedBackend + 'tx> Transactional<'tx> for Store<B> {
    type TransactionRo = StoreTxRo<'tx, B>;
    type TransactionRw = StoreTxRw<'tx, B>;

    #[log_error]
    fn transaction_ro<'st: 'tx>(&'st self) -> crate::Result<Self::TransactionRo> {
        self.0.transaction_ro().map_err(crate::Error::from).map(StoreTxRo)
    }

    #[log_error]
    fn transaction_rw<'st: 'tx>(
        &'st self,
        size: Option<usize>,
    ) -> crate::Result<Self::TransactionRw> {
        <storage::Storage<_, _> as storage::StorageSharedWrite<_, _>>::transaction_rw(&self.0, size)
            .map_err(crate::Error::from)
            .map(StoreTxRw::new)
    }
}

impl<B: storage::SharedBackend + 'static> BlockchainStorage for Store<B> {}

impl<B: storage::SharedBackend> PoSAccountingStorageRead<TipStorageTag> for Store<B> {
    type Error = crate::Error;

    #[log_error]
    fn get_pool_balance(&self, pool_id: PoolId) -> crate::Result<Option<Amount>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tx, pool_id)
    }
    #[log_error]
    fn get_pool_data(&self, pool_id: PoolId) -> crate::Result<Option<PoolData>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_data(&tx, pool_id)
    }
    #[log_error]
    fn get_delegation_balance(&self, delegation_id: DelegationId) -> crate::Result<Option<Amount>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(&tx, delegation_id)
    }
    #[log_error]
    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<DelegationData>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<TipStorageTag>::get_delegation_data(&tx, delegation_id)
    }
    #[log_error]
    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> crate::Result<Option<BTreeMap<DelegationId, Amount>>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_delegations_shares(&tx, pool_id)
    }
    #[log_error]
    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<Amount>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_delegation_share(
            &tx,
            pool_id,
            delegation_id,
        )
    }
}

impl<B: storage::SharedBackend> PoSAccountingStorageRead<SealedStorageTag> for Store<B> {
    type Error = crate::Error;

    #[log_error]
    fn get_pool_balance(&self, pool_id: PoolId) -> crate::Result<Option<Amount>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<SealedStorageTag>::get_pool_balance(&tx, pool_id)
    }
    #[log_error]
    fn get_pool_data(&self, pool_id: PoolId) -> crate::Result<Option<PoolData>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<SealedStorageTag>::get_pool_data(&tx, pool_id)
    }
    #[log_error]
    fn get_delegation_balance(&self, delegation_id: DelegationId) -> crate::Result<Option<Amount>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<SealedStorageTag>::get_delegation_balance(&tx, delegation_id)
    }
    #[log_error]
    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<DelegationData>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<SealedStorageTag>::get_delegation_data(&tx, delegation_id)
    }
    #[log_error]
    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> crate::Result<Option<BTreeMap<DelegationId, Amount>>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<SealedStorageTag>::get_pool_delegations_shares(&tx, pool_id)
    }
    #[log_error]
    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<Amount>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<SealedStorageTag>::get_pool_delegation_share(
            &tx,
            pool_id,
            delegation_id,
        )
    }
}

impl<B: storage::SharedBackend> PoSAccountingStorageWrite<TipStorageTag> for Store<B> {
    #[log_error]
    fn set_pool_balance(&mut self, pool_id: PoolId, amount: Amount) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<TipStorageTag>::set_pool_balance(&mut tx, pool_id, amount)?;
        tx.commit()
    }
    #[log_error]
    fn del_pool_balance(&mut self, pool_id: PoolId) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<TipStorageTag>::del_pool_balance(&mut tx, pool_id)?;
        tx.commit()
    }

    #[log_error]
    fn set_pool_data(&mut self, pool_id: PoolId, pool_data: &PoolData) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<TipStorageTag>::set_pool_data(&mut tx, pool_id, pool_data)?;
        tx.commit()
    }

    #[log_error]
    fn del_pool_data(&mut self, pool_id: PoolId) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<TipStorageTag>::del_pool_data(&mut tx, pool_id)?;
        tx.commit()
    }

    #[log_error]
    fn set_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
        amount: Amount,
    ) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<TipStorageTag>::set_delegation_balance(
            &mut tx,
            delegation_target,
            amount,
        )?;
        tx.commit()
    }

    #[log_error]
    fn del_delegation_balance(&mut self, delegation_target: DelegationId) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<TipStorageTag>::del_delegation_balance(
            &mut tx,
            delegation_target,
        )?;
        tx.commit()
    }

    #[log_error]
    fn set_delegation_data(
        &mut self,
        delegation_target: DelegationId,
        delegation_data: &DelegationData,
    ) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<TipStorageTag>::set_delegation_data(
            &mut tx,
            delegation_target,
            delegation_data,
        )?;
        tx.commit()
    }

    #[log_error]
    fn del_delegation_data(
        &mut self,
        delegation_id: DelegationId,
    ) -> Result<(), chainstate_types::storage_result::Error> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<TipStorageTag>::del_delegation_data(&mut tx, delegation_id)?;
        tx.commit()
    }

    #[log_error]
    fn set_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> Result<(), chainstate_types::storage_result::Error> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<TipStorageTag>::set_pool_delegation_share(
            &mut tx,
            pool_id,
            delegation_id,
            amount,
        )?;
        tx.commit()
    }

    #[log_error]
    fn del_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<(), chainstate_types::storage_result::Error> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<TipStorageTag>::del_pool_delegation_share(
            &mut tx,
            pool_id,
            delegation_id,
        )?;
        tx.commit()
    }
}

impl<B: storage::SharedBackend> PoSAccountingStorageWrite<SealedStorageTag> for Store<B> {
    #[log_error]
    fn set_pool_balance(&mut self, pool_id: PoolId, amount: Amount) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<SealedStorageTag>::set_pool_balance(&mut tx, pool_id, amount)?;
        tx.commit()
    }
    #[log_error]
    fn del_pool_balance(&mut self, pool_id: PoolId) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<SealedStorageTag>::del_pool_balance(&mut tx, pool_id)?;
        tx.commit()
    }

    #[log_error]
    fn set_pool_data(&mut self, pool_id: PoolId, pool_data: &PoolData) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<SealedStorageTag>::set_pool_data(&mut tx, pool_id, pool_data)?;
        tx.commit()
    }

    #[log_error]
    fn del_pool_data(&mut self, pool_id: PoolId) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<SealedStorageTag>::del_pool_data(&mut tx, pool_id)?;
        tx.commit()
    }

    #[log_error]
    fn del_delegation_balance(&mut self, delegation_target: DelegationId) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<SealedStorageTag>::del_delegation_balance(
            &mut tx,
            delegation_target,
        )?;
        tx.commit()
    }

    #[log_error]
    fn set_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
        amount: Amount,
    ) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<SealedStorageTag>::set_delegation_balance(
            &mut tx,
            delegation_target,
            amount,
        )?;
        tx.commit()
    }

    #[log_error]
    fn set_delegation_data(
        &mut self,
        delegation_target: DelegationId,
        delegation_data: &DelegationData,
    ) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<SealedStorageTag>::set_delegation_data(
            &mut tx,
            delegation_target,
            delegation_data,
        )?;
        tx.commit()
    }

    #[log_error]
    fn del_delegation_data(
        &mut self,
        delegation_id: DelegationId,
    ) -> Result<(), chainstate_types::storage_result::Error> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<SealedStorageTag>::del_delegation_data(&mut tx, delegation_id)?;
        tx.commit()
    }

    #[log_error]
    fn set_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<SealedStorageTag>::set_pool_delegation_share(
            &mut tx,
            pool_id,
            delegation_id,
            amount,
        )?;
        tx.commit()
    }

    #[log_error]
    fn del_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<SealedStorageTag>::del_pool_delegation_share(
            &mut tx,
            pool_id,
            delegation_id,
        )?;
        tx.commit()
    }
}

#[cfg(test)]
mod test;
