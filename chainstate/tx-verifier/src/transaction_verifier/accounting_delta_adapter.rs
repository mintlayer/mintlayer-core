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
    chain::{OutPoint, PoolId},
    primitives::Amount,
};
use pos_accounting::{
    DeltaMergeUndo, FlushablePoSAccountingView, PoSAccountingDelta, PoSAccountingDeltaData,
    PoSAccountingOperations, PoSAccountingUndo, PoSAccountingView, PoolData,
};

/// Adapter over `PosAccountingDelta` that implements `PoSAccountingOperations`.
/// Main purpose of this struct is to make it impossible to perform operations on current delta
/// and forget to update cumulative blocks delta.
pub struct PoSAccountingDeltaAdapter<P> {
    // represents accumulated delta with all changes done via current verifier object
    accounting_delta: PoSAccountingDelta<P>,

    // stores deltas per block
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

impl<'a, P: PoSAccountingView> PoSAccountingOperations for PoSAccountingOperationImpl<'a, P> {
    fn create_pool(
        &mut self,
        input0_outpoint: &OutPoint,
        pool_data: PoolData,
    ) -> Result<(PoolId, PoSAccountingUndo), pos_accounting::Error> {
        let mut delta = PoSAccountingDelta::new(&self.adapter.accounting_delta);
        let (pool_id, undo) = delta.create_pool(input0_outpoint, pool_data)?;

        self.merge_delta(delta.consume())?;

        Ok((pool_id, undo))
    }

    fn decommission_pool(
        &mut self,
        pool_id: PoolId,
    ) -> Result<PoSAccountingUndo, pos_accounting::Error> {
        let mut delta = PoSAccountingDelta::new(&self.adapter.accounting_delta);

        let undo = delta.decommission_pool(pool_id)?;

        self.merge_delta(delta.consume())?;

        Ok(undo)
    }

    fn increase_pool_balance(
        &mut self,
        pool_id: PoolId,
        amount_to_add: Amount,
    ) -> Result<PoSAccountingUndo, pos_accounting::Error> {
        let mut delta = PoSAccountingDelta::new(&self.adapter.accounting_delta);

        let undo = delta.increase_pool_balance(pool_id, amount_to_add)?;

        self.merge_delta(delta.consume())?;

        Ok(undo)
    }

    fn create_delegation_id(
        &mut self,
        _target_pool: PoolId,
        _spend_key: common::chain::Destination,
        _input0_outpoint: &OutPoint,
    ) -> Result<(common::chain::DelegationId, PoSAccountingUndo), pos_accounting::Error> {
        unimplemented!()
    }

    fn delegate_staking(
        &mut self,
        _delegation_target: common::chain::DelegationId,
        _amount_to_delegate: Amount,
    ) -> Result<PoSAccountingUndo, pos_accounting::Error> {
        unimplemented!()
    }

    fn spend_share_from_delegation_id(
        &mut self,
        _delegation_id: common::chain::DelegationId,
        _amount: Amount,
    ) -> Result<PoSAccountingUndo, pos_accounting::Error> {
        unimplemented!()
    }

    fn undo(&mut self, undo: PoSAccountingUndo) -> Result<(), pos_accounting::Error> {
        let mut delta = PoSAccountingDelta::new(&self.adapter.accounting_delta);

        delta.undo(undo)?;

        self.merge_delta(delta.consume())
    }
}
// TODO: unit tests
