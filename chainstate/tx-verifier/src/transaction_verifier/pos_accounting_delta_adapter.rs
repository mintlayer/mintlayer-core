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

use super::{storage::TransactionVerifierStorageError, TransactionSource};

use common::{
    chain::{DelegationId, PoolId},
    primitives::Amount,
};
use logging::log;
use pos_accounting::{
    DeltaMergeUndo, FlushablePoSAccountingView, PoSAccountingDelta, PoSAccountingDeltaData,
    PoSAccountingOperations, PoSAccountingUndo, PoSAccountingView, PoolData,
};

/// Adapter over `PosAccountingDelta` that implements `PoSAccountingOperations`.
/// Main purpose of this struct is to make it impossible to perform operations on current delta
/// and forget to update cumulative blocks delta.
pub struct PoSAccountingDeltaAdapter<P> {
    // This represents accumulated delta with all changes done via current verifier object.
    accounting_delta: PoSAccountingDelta<P>,

    // This stores deltas per block.
    // Note/TODO:
    // 1) This map mainly exists to be able to update epoch data later, for which the block height
    // must be known (which will be obtained from the block id).
    // (The map will become `pos_accounting_block_deltas` of the `TransactionVerifierDelta` that will be
    // passed to `flush_to_storage`, which will call `TransactionVerifierStorage::apply_accounting_delta`
    // on it, which will merge the delta into the corresponding epoch delta).
    // 2) The fact that it's a map from `TransactionSource` is actually a mistake, because it doesn't reflect
    // the order of the blocks. Because of this, `flush_to_storage` will only work correctly if the size of the map
    // is not bigger than 1 (and it has the corresponding debug assert).
    // 3) We'd probably still want to be able to use the same `TransactionVerifier` object to accumulate deltas from
    // multiple consecutive blocks (though we don't currently have a use-case for it).
    // So, TODO: make it a linear collection ordered by block height (OR include the block height into the source so that
    // `flush_to_storage` can do the sorting).
    // Also note that we don't really want to re-use the same tx verifier for both blocks' and mempool's transactions,
    // so the field should become an enum containing either one delta for the mempool or multiple deltas for consecutive
    // blocks.
    // Finally note that we have this old TODO all over the place suggesting moving the "TransactionSource::Chain" vs "::Mempool"
    // distinction to compile time (mintlayer-core/issues/633), which means that instead of the single `TransactionSource` enum
    // we'll have 2 separate types, one of which will be provided as a generic parameter in places where `TransactionSource`
    // is currently passed at run-time. If we go this route, then this field can't be an enum either and its type will have to be
    // provided as a generic parameter as well.
    accounting_block_deltas: BTreeMap<TransactionSource, PoSAccountingDeltaData>,
}

impl<P: PoSAccountingView> PoSAccountingDeltaAdapter<P> {
    pub fn new(parent: P) -> Self {
        Self {
            accounting_delta: PoSAccountingDelta::new(parent),
            accounting_block_deltas: BTreeMap::new(),
        }
    }

    pub fn consume(
        self,
    ) -> (
        PoSAccountingDeltaData,
        BTreeMap<TransactionSource, PoSAccountingDeltaData>,
    ) {
        (
            self.accounting_delta.consume(),
            self.accounting_block_deltas,
        )
    }

    pub fn operations(&mut self, tx_source: TransactionSource) -> PoSAccountingOperationImpl<P> {
        PoSAccountingOperationImpl::new(self, tx_source)
    }

    pub fn accounting_delta(&self) -> &PoSAccountingDelta<P> {
        &self.accounting_delta
    }

    pub fn batch_write_delta(
        &mut self,
        data: PoSAccountingDeltaData,
    ) -> Result<DeltaMergeUndo, pos_accounting::Error> {
        self.accounting_delta.batch_write_delta(data)
    }

    pub fn apply_accounting_delta(
        &mut self,
        tx_source: TransactionSource,
        delta: &PoSAccountingDeltaData,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.accounting_block_deltas
            .entry(tx_source)
            .or_default()
            .merge_with_delta(delta.clone())?;
        Ok(())
    }
}

pub struct PoSAccountingOperationImpl<'a, P> {
    adapter: &'a mut PoSAccountingDeltaAdapter<P>,
    tx_source: TransactionSource,
}

impl<'a, P: PoSAccountingView> PoSAccountingOperationImpl<'a, P> {
    fn new(adapter: &'a mut PoSAccountingDeltaAdapter<P>, tx_source: TransactionSource) -> Self {
        Self { adapter, tx_source }
    }

    fn merge_delta(&mut self, delta: PoSAccountingDeltaData) -> Result<(), pos_accounting::Error> {
        self.adapter.accounting_delta.merge_with_delta(delta.clone())?;
        self.adapter
            .accounting_block_deltas
            .entry(self.tx_source)
            .or_default()
            .merge_with_delta(delta)?;
        Ok(())
    }
}

impl<P: PoSAccountingView> PoSAccountingView for PoSAccountingOperationImpl<'_, P> {
    type Error = pos_accounting::Error;

    fn pool_exists(&self, pool_id: PoolId) -> Result<bool, Self::Error> {
        self.adapter.accounting_delta.pool_exists(pool_id)
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Self::Error> {
        self.adapter.accounting_delta.get_pool_data(pool_id)
    }

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Amount, Self::Error> {
        self.adapter.accounting_delta.get_pool_balance(pool_id)
    }

    fn get_delegation_data(
        &self,
        delegation_id: common::chain::DelegationId,
    ) -> Result<Option<pos_accounting::DelegationData>, Self::Error> {
        self.adapter.accounting_delta.get_delegation_data(delegation_id)
    }

    fn get_delegation_balance(
        &self,
        delegation_id: common::chain::DelegationId,
    ) -> Result<Amount, Self::Error> {
        self.adapter.accounting_delta.get_delegation_balance(delegation_id)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: common::chain::DelegationId,
    ) -> Result<Amount, Self::Error> {
        self.adapter.accounting_delta.get_pool_delegation_share(pool_id, delegation_id)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<common::chain::DelegationId, Amount>>, Self::Error> {
        self.adapter.accounting_delta.get_pool_delegations_shares(pool_id)
    }
}

impl<P: PoSAccountingView> PoSAccountingOperations<PoSAccountingUndo>
    for PoSAccountingOperationImpl<'_, P>
{
    fn create_pool(
        &mut self,
        pool_id: PoolId,
        pool_data: PoolData,
    ) -> Result<PoSAccountingUndo, pos_accounting::Error> {
        log::debug!("Creating a pool: {}", pool_id);

        let mut delta = PoSAccountingDelta::new(&self.adapter.accounting_delta);
        let undo = delta.create_pool(pool_id, pool_data)?;

        self.merge_delta(delta.consume())?;

        Ok(undo)
    }

    fn decommission_pool(
        &mut self,
        pool_id: PoolId,
    ) -> Result<PoSAccountingUndo, pos_accounting::Error> {
        log::debug!("Decommissioning a pool: {}", pool_id);

        let mut delta = PoSAccountingDelta::new(&self.adapter.accounting_delta);

        let undo = delta.decommission_pool(pool_id)?;

        self.merge_delta(delta.consume())?;

        Ok(undo)
    }

    fn increase_staker_rewards(
        &mut self,
        pool_id: PoolId,
        amount_to_add: Amount,
    ) -> Result<PoSAccountingUndo, pos_accounting::Error> {
        log::debug!("Increasing staker reward of pool: {:x}", pool_id);

        let mut delta = PoSAccountingDelta::new(&self.adapter.accounting_delta);

        let undo = delta.increase_staker_rewards(pool_id, amount_to_add)?;

        self.merge_delta(delta.consume())?;

        Ok(undo)
    }

    fn create_delegation_id(
        &mut self,
        target_pool: PoolId,
        delegation_id: DelegationId,
        spend_key: common::chain::Destination,
    ) -> Result<PoSAccountingUndo, pos_accounting::Error> {
        let mut delta = PoSAccountingDelta::new(&self.adapter.accounting_delta);

        let undo = delta.create_delegation_id(target_pool, delegation_id, spend_key)?;

        log::debug!(
            "Creating a delegation: {} for pool {}",
            delegation_id,
            target_pool
        );

        self.merge_delta(delta.consume())?;

        Ok(undo)
    }

    fn delete_delegation_id(
        &mut self,
        delegation_id: common::chain::DelegationId,
    ) -> Result<PoSAccountingUndo, pos_accounting::Error> {
        log::debug!("Deleting a delegation: {}", delegation_id);

        let mut delta = PoSAccountingDelta::new(&self.adapter.accounting_delta);

        let undo = delta.delete_delegation_id(delegation_id)?;

        self.merge_delta(delta.consume())?;

        Ok(undo)
    }

    fn delegate_staking(
        &mut self,
        delegation_target: common::chain::DelegationId,
        amount_to_delegate: Amount,
    ) -> Result<PoSAccountingUndo, pos_accounting::Error> {
        log::debug!(
            "Delegating {:?} coins to {}",
            amount_to_delegate,
            delegation_target
        );

        let mut delta = PoSAccountingDelta::new(&self.adapter.accounting_delta);

        let undo = delta.delegate_staking(delegation_target, amount_to_delegate)?;

        self.merge_delta(delta.consume())?;

        Ok(undo)
    }

    fn spend_share_from_delegation_id(
        &mut self,
        delegation_id: common::chain::DelegationId,
        amount: Amount,
    ) -> Result<PoSAccountingUndo, pos_accounting::Error> {
        log::debug!(
            "Spending {:?} coins from delegation {}",
            amount,
            delegation_id
        );

        let mut delta = PoSAccountingDelta::new(&self.adapter.accounting_delta);

        let undo = delta.spend_share_from_delegation_id(delegation_id, amount)?;

        self.merge_delta(delta.consume())?;

        Ok(undo)
    }

    fn undo(&mut self, undo: PoSAccountingUndo) -> Result<(), pos_accounting::Error> {
        log::debug!("Undo {:?} ", undo);
        let mut delta = PoSAccountingDelta::new(&self.adapter.accounting_delta);

        delta.undo(undo)?;

        self.merge_delta(delta.consume())
    }
}

// TODO: unit tests
