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

use super::{
    error::ConnectTransactionError, storage::TransactionVerifierStorageError, TransactionSource,
};
use common::{
    chain::{stakelock::StakePoolData, OutPoint, PoolId},
    primitives::Amount,
};
use pos_accounting::{
    DeltaMergeUndo, FlushablePoSAccountingView, PoSAccountingDelta, PoSAccountingDeltaData,
    PoSAccountingOperations, PoSAccountingUndo, PoSAccountingView,
};

/// Adapter over `PosAccountingDelta` that mimics `PoSAccountingOperations`.
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

    pub fn get_accounting_delta(&self) -> &PoSAccountingDelta<P> {
        &self.accounting_delta
    }

    pub fn create_pool(
        &mut self,
        tx_source: TransactionSource,
        pool_data: &StakePoolData,
        input0_outpoint: &OutPoint,
    ) -> Result<(PoolId, PoSAccountingUndo), ConnectTransactionError> {
        // TODO: check StakePoolData fields
        let delegation_amount = pool_data.value();

        let mut temp_delta = PoSAccountingDelta::new(&self.accounting_delta);
        let (pool_id, undo) = temp_delta.create_pool(
            input0_outpoint,
            delegation_amount,
            pool_data.decommission_key().clone(),
            pool_data.vrf_public_key().clone(),
            pool_data.margin_ratio_per_thousand(),
            pool_data.cost_per_epoch(),
        )?;

        let new_delta_data = temp_delta.consume();
        self.accounting_delta.merge_with_delta(new_delta_data.clone())?;
        self.accounting_block_deltas
            .entry(tx_source)
            .or_default()
            .merge_with_delta(new_delta_data)?;

        Ok((pool_id, undo))
    }

    pub fn decommission_pool(
        &mut self,
        tx_source: TransactionSource,
        pool_id: PoolId,
    ) -> Result<PoSAccountingUndo, ConnectTransactionError> {
        let mut temp_delta = PoSAccountingDelta::new(&self.accounting_delta);

        let undo = temp_delta.decommission_pool(pool_id)?;

        let new_delta_data = temp_delta.consume();
        self.accounting_delta.merge_with_delta(new_delta_data.clone())?;
        self.accounting_block_deltas
            .entry(tx_source)
            .or_default()
            .merge_with_delta(new_delta_data)?;
        Ok(undo)
    }

    pub fn increase_pool_balance(
        &mut self,
        tx_source: TransactionSource,
        pool_id: PoolId,
        amount_to_add: Amount,
    ) -> Result<PoSAccountingUndo, ConnectTransactionError> {
        let mut temp_delta = PoSAccountingDelta::new(&self.accounting_delta);

        let undo = temp_delta.increase_pool_balance(pool_id, amount_to_add)?;

        let new_delta_data = temp_delta.consume();
        self.accounting_delta.merge_with_delta(new_delta_data.clone())?;
        self.accounting_block_deltas
            .entry(tx_source)
            .or_default()
            .merge_with_delta(new_delta_data)?;
        Ok(undo)
    }

    pub fn undo(
        &mut self,
        tx_source: TransactionSource,
        undo: PoSAccountingUndo,
    ) -> Result<(), ConnectTransactionError> {
        let mut temp_delta = PoSAccountingDelta::new(&self.accounting_delta);
        temp_delta.undo(undo)?;
        let new_delta_data = temp_delta.consume();

        self.accounting_delta.merge_with_delta(new_delta_data.clone())?;
        self.accounting_block_deltas
            .entry(tx_source)
            .or_default()
            .merge_with_delta(new_delta_data)?;
        Ok(())
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
