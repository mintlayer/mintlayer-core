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

use std::collections::btree_map::Entry;

use super::{
    cached_inputs_operation::CachedInputsOperation,
    error::{ConnectTransactionError, TxIndexError},
};
use common::chain::{OutPointSourceId, Spender, TxInput, TxMainChainIndex};

pub type TxIndexMap = std::collections::BTreeMap<OutPointSourceId, CachedInputsOperation>;

pub struct TxIndexCache {
    data: TxIndexMap,
}

impl TxIndexCache {
    pub fn new() -> Self {
        Self {
            data: TxIndexMap::new(),
        }
    }

    #[cfg(test)]
    pub fn new_for_test(data: TxIndexMap) -> Self {
        Self { data }
    }

    pub fn consume(self) -> TxIndexMap {
        self.data
    }

    pub fn add_tx_index(
        &mut self,
        outpoint_source_id: OutPointSourceId,
        tx_index: TxMainChainIndex,
    ) -> Result<(), TxIndexError> {
        match self.data.entry(outpoint_source_id) {
            Entry::Occupied(_) => {
                return Err(TxIndexError::OutputAlreadyPresentInInputsCache);
            }
            Entry::Vacant(entry) => {
                entry.insert(CachedInputsOperation::Write(tx_index));
            }
        };

        Ok(())
    }

    pub fn remove_tx_index(
        &mut self,
        outpoint_source_id: OutPointSourceId,
    ) -> Result<(), TxIndexError> {
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

    pub fn precache_inputs<F, E>(
        &mut self,
        inputs: &[TxInput],
        fetcher_func: F,
    ) -> Result<(), ConnectTransactionError>
    where
        F: Fn(&OutPointSourceId) -> Result<Option<TxMainChainIndex>, E>,
        ConnectTransactionError: From<E>,
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
