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

use common::{
    chain::{
        calculate_tx_index_from_block, signature::Signable, OutPoint, OutPointSourceId, Spender,
        TxInput, TxMainChainIndex,
    },
    primitives::Idable,
};

use crate::ConnectTransactionError;

use super::{cached_operation::CachedInputsOperation, BlockTransactableRef};

pub struct TxIndexCache {
    data: BTreeMap<OutPointSourceId, CachedInputsOperation>,
}

impl TxIndexCache {
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }

    pub fn add_tx_index(
        &mut self,
        spend_ref: BlockTransactableRef,
    ) -> Result<(), ConnectTransactionError> {
        let tx_index = match spend_ref {
            BlockTransactableRef::Transaction(block, tx_num) => {
                CachedInputsOperation::Write(calculate_tx_index_from_block(block, tx_num)?)
            }
            BlockTransactableRef::BlockReward(block) => {
                match block.block_reward_transactable().outputs() {
                    Some(outputs) => CachedInputsOperation::Write(TxMainChainIndex::new(
                        block.get_id().into(),
                        outputs
                            .len()
                            .try_into()
                            .map_err(|_| ConnectTransactionError::InvalidOutputCount)?,
                    )?),
                    None => return Ok(()), // no outputs to add
                }
            }
        };

        let outpoint_source_id = Self::outpoint_source_id_from_spend_ref(spend_ref)?;

        match self.data.entry(outpoint_source_id) {
            Entry::Occupied(_) => {
                return Err(ConnectTransactionError::OutputAlreadyPresentInInputsCache)
            }
            Entry::Vacant(entry) => entry.insert(tx_index),
        };
        Ok(())
    }

    pub fn remove_tx_index(
        &mut self,
        spend_ref: BlockTransactableRef,
    ) -> Result<(), ConnectTransactionError> {
        let tx_index = CachedInputsOperation::Erase;
        let outpoint_source_id = Self::outpoint_source_id_from_spend_ref(spend_ref)?;

        self.data.insert(outpoint_source_id, tx_index);
        Ok(())
    }

    fn fetch_and_cache<F>(
        &mut self,
        outpoint: &OutPoint,
        fetcher_func: F,
    ) -> Result<(), ConnectTransactionError>
    where
        F: Fn(&OutPointSourceId) -> Result<Option<TxMainChainIndex>, ConnectTransactionError>,
    {
        match self.data.entry(outpoint.tx_id()) {
            Entry::Occupied(_) => (),
            Entry::Vacant(entry) => {
                // Maybe the utxo is in a previous block?
                let tx_index = fetcher_func(&outpoint.tx_id())?
                    .ok_or(ConnectTransactionError::MissingOutputOrSpent)?;
                entry.insert(CachedInputsOperation::Read(tx_index));
            }
        }
        Ok(())
    }

    fn outpoint_source_id_from_spend_ref(
        spend_ref: BlockTransactableRef,
    ) -> Result<OutPointSourceId, ConnectTransactionError> {
        let outpoint_source_id = match spend_ref {
            BlockTransactableRef::Transaction(block, tx_num) => {
                let tx = block.transactions().get(tx_num).ok_or_else(|| {
                    ConnectTransactionError::InvariantErrorTxNumWrongInBlock(tx_num, block.get_id())
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
    ) -> Result<&mut CachedInputsOperation, ConnectTransactionError> {
        let result = match self.data.get_mut(outpoint) {
            Some(tx_index) => tx_index,
            None => {
                return Err(ConnectTransactionError::PreviouslyCachedInputNotFound(
                    outpoint.clone(),
                ))
            }
        };
        Ok(result)
    }

    pub fn spend_tx_index_inputs(
        &mut self,
        inputs: &[TxInput],
        spender: Spender,
    ) -> Result<(), ConnectTransactionError> {
        for input in inputs {
            let outpoint = input.outpoint();
            let prev_tx_index_op = self.get_from_cached_mut(&outpoint.tx_id())?;
            prev_tx_index_op
                .spend(outpoint.output_index(), spender.clone())
                .map_err(ConnectTransactionError::from)?;
        }

        Ok(())
    }

    pub fn unspend_tx_index_inputs(
        &mut self,
        inputs: &[TxInput],
    ) -> Result<(), ConnectTransactionError> {
        for input in inputs {
            let outpoint = input.outpoint();
            let prev_tx_index_op = self.get_from_cached_mut(&outpoint.tx_id())?;
            prev_tx_index_op
                .unspend(outpoint.output_index())
                .map_err(ConnectTransactionError::from)?;
        }

        Ok(())
    }

    pub fn precache_inputs<F>(
        &mut self,
        inputs: &[TxInput],
        fetcher_func: F,
    ) -> Result<(), ConnectTransactionError>
    where
        F: Fn(&OutPointSourceId) -> Result<Option<TxMainChainIndex>, ConnectTransactionError>,
    {
        inputs.iter().try_for_each(|input| {
            self.fetch_and_cache(input.outpoint(), |txid| {
                fetcher_func(txid).map_err(ConnectTransactionError::from)
            })
        })
    }

    pub fn take(self) -> BTreeMap<OutPointSourceId, CachedInputsOperation> {
        self.data
    }
}

// TODO: write tests
