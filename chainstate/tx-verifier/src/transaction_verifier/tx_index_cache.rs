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

use std::collections::{btree_map::Entry, BTreeMap};

use super::{
    error::{ConnectTransactionError, TxIndexError},
    storage::TransactionVerifierStorageError,
    {cached_operation::CachedInputsOperation, BlockTransactableRef},
};
use common::{
    chain::{signature::Signable, OutPointSourceId, Spender, TxInput, TxMainChainIndex},
    primitives::Idable,
};

pub struct TxIndexCache {
    data: BTreeMap<OutPointSourceId, CachedInputsOperation>,
}

impl TxIndexCache {
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }

    #[cfg(test)]
    pub fn new_for_test(data: BTreeMap<OutPointSourceId, CachedInputsOperation>) -> Self {
        Self { data }
    }

    pub fn consume(self) -> BTreeMap<OutPointSourceId, CachedInputsOperation> {
        self.data
    }

    pub fn add_tx_index(
        &mut self,
        spend_ref: BlockTransactableRef,
        tx_index: TxMainChainIndex,
    ) -> Result<(), TxIndexError> {
        let outpoint_source_id = Self::outpoint_source_id_from_spend_ref(&spend_ref)?;

        let tx_index = match spend_ref {
            BlockTransactableRef::Transaction(_block, _tx_num) => {
                CachedInputsOperation::Write(tx_index)
            }
            BlockTransactableRef::BlockReward(block) => {
                match block.block_reward_transactable().outputs() {
                    Some(outputs) => CachedInputsOperation::Write(TxMainChainIndex::new(
                        block.get_id().into(),
                        outputs.len().try_into().map_err(|_| TxIndexError::InvalidOutputCount)?,
                    )?),
                    None => return Ok(()), // no outputs to add
                }
            }
        };

        match self.data.entry(outpoint_source_id) {
            Entry::Occupied(_) => {
                return Err(TxIndexError::OutputAlreadyPresentInInputsCache);
            }
            Entry::Vacant(entry) => {
                entry.insert(tx_index);
            }
        };

        Ok(())
    }

    pub fn remove_tx_index(&mut self, spend_ref: BlockTransactableRef) -> Result<(), TxIndexError> {
        let outpoint_source_id = Self::outpoint_source_id_from_spend_ref(&spend_ref)?;
        self.remove_tx_index_by_id(outpoint_source_id)
    }

    pub fn remove_tx_index_by_id(&mut self, tx_id: OutPointSourceId) -> Result<(), TxIndexError> {
        // possible overwrite is ok
        self.data.insert(tx_id, CachedInputsOperation::Erase);
        Ok(())
    }

    pub fn set_tx_index(
        &mut self,
        tx_id: &OutPointSourceId,
        tx_index: TxMainChainIndex,
    ) -> Result<(), TxIndexError> {
        // possible overwrite is ok
        self.data.insert(tx_id.clone(), CachedInputsOperation::Write(tx_index));
        Ok(())
    }

    fn outpoint_source_id_from_spend_ref(
        spend_ref: &BlockTransactableRef,
    ) -> Result<OutPointSourceId, TxIndexError> {
        let outpoint_source_id = match spend_ref {
            BlockTransactableRef::Transaction(block, tx_num) => {
                let tx = block.transactions().get(*tx_num).ok_or_else(|| {
                    TxIndexError::InvariantErrorTxNumWrongInBlock(*tx_num, block.get_id())
                })?;
                let tx_id = tx.transaction().get_id();
                OutPointSourceId::from(tx_id)
            }
            BlockTransactableRef::BlockReward(block) => OutPointSourceId::from(block.get_id()),
        };
        Ok(outpoint_source_id)
    }

    fn get_from_cached_mut(
        &mut self,
        outpoint: &OutPointSourceId,
    ) -> Result<&mut CachedInputsOperation, TxIndexError> {
        match self.data.get_mut(outpoint) {
            Some(tx_index) => Ok(tx_index),
            None => Err(TxIndexError::PreviouslyCachedInputNotFound(
                outpoint.clone(),
            )),
        }
    }

    pub fn get_from_cached(&self, outpoint: &OutPointSourceId) -> Option<&CachedInputsOperation> {
        self.data.get(outpoint)
    }

    pub fn spend_tx_index_inputs(
        &mut self,
        inputs: &[TxInput],
        spender: Spender,
    ) -> Result<(), TxIndexError> {
        for input in inputs {
            let outpoint = input.outpoint();
            let prev_tx_index_op = self.get_from_cached_mut(&outpoint.tx_id())?;
            prev_tx_index_op
                .spend(outpoint.output_index(), spender.clone())
                .map_err(TxIndexError::from)?;
        }

        Ok(())
    }

    pub fn unspend_tx_index_inputs(&mut self, inputs: &[TxInput]) -> Result<(), TxIndexError> {
        for input in inputs {
            let outpoint = input.outpoint();
            let prev_tx_index_op = self.get_from_cached_mut(&outpoint.tx_id())?;
            prev_tx_index_op.unspend(outpoint.output_index()).map_err(TxIndexError::from)?;
        }

        Ok(())
    }

    pub fn precache_inputs<F>(
        &mut self,
        inputs: &[TxInput],
        fetcher_func: F,
    ) -> Result<(), ConnectTransactionError>
    where
        F: Fn(
            &OutPointSourceId,
        ) -> Result<Option<TxMainChainIndex>, TransactionVerifierStorageError>,
    {
        inputs.iter().try_for_each(|input| {
            let outpoint = input.outpoint();
            match self.data.entry(outpoint.tx_id()) {
                Entry::Occupied(_) => (),
                Entry::Vacant(entry) => {
                    // Maybe the utxo is in a previous block?
                    let tx_index = fetcher_func(&outpoint.tx_id())?
                        .ok_or(TxIndexError::MissingOutputOrSpent)?;
                    entry.insert(CachedInputsOperation::Read(tx_index));
                }
            }
            Ok(())
        })
    }
}

// TODO: write tests
