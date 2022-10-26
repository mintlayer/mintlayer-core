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

use std::sync::Arc;

use ::tx_verifier::transaction_verifier::storage::{
    TransactionVerifierStorageError, TransactionVerifierStorageMut, TransactionVerifierStorageRef,
};
use chainstate_storage::{inmemory::Store, BlockchainStorageRead, BlockchainStorageWrite};
use chainstate_types::{storage_result, GenBlockIndex};
use common::{
    chain::{
        tokens::{TokenAuxiliaryData, TokenId},
        Block, ChainConfig, GenBlock, GenBlockId, OutPointSourceId, Transaction, TxMainChainIndex,
    },
    primitives::Id,
};
use utxo::{ConsumedUtxoCache, FlushableUtxoView, UtxosDBMut, UtxosStorageRead, UtxosStorageWrite};

pub struct InMemoryStorageWrapper {
    storage: Store,
    chain_config: ChainConfig,
}

impl InMemoryStorageWrapper {
    pub fn new(storage: Store, chain_config: ChainConfig) -> Self {
        Self {
            storage,
            chain_config,
        }
    }
}

impl TransactionVerifierStorageRef for InMemoryStorageWrapper {
    fn get_token_id_from_issuance_tx(
        &self,
        tx_id: Id<Transaction>,
    ) -> Result<Option<TokenId>, TransactionVerifierStorageError> {
        self.storage.get_token_id(&tx_id).map_err(TransactionVerifierStorageError::from)
    }

    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, storage_result::Error> {
        match block_id.classify(&self.chain_config) {
            GenBlockId::Genesis(_id) => Ok(Some(GenBlockIndex::Genesis(Arc::clone(
                self.chain_config.genesis_block(),
            )))),
            GenBlockId::Block(id) => {
                self.storage.get_block_index(&id).map(|b| b.map(GenBlockIndex::Block))
            }
        }
    }

    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<TxMainChainIndex>, TransactionVerifierStorageError> {
        self.storage
            .get_mainchain_tx_index(tx_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn get_token_aux_data(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<TokenAuxiliaryData>, TransactionVerifierStorageError> {
        self.storage
            .get_token_aux_data(token_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn get_mempool_undo_data(
        &self,
    ) -> Result<Option<utxo::BlockUndo>, TransactionVerifierStorageError> {
        Ok(None)
    }
}

impl UtxosStorageRead for InMemoryStorageWrapper {
    fn get_utxo(
        &self,
        outpoint: &common::chain::OutPoint,
    ) -> Result<Option<utxo::Utxo>, chainstate_types::storage_result::Error> {
        self.storage.get_utxo(outpoint)
    }

    fn get_best_block_for_utxos(
        &self,
    ) -> Result<Option<Id<GenBlock>>, chainstate_types::storage_result::Error> {
        self.storage.get_best_block_for_utxos()
    }

    fn get_undo_data(
        &self,
        id: Id<Block>,
    ) -> Result<Option<utxo::BlockUndo>, chainstate_types::storage_result::Error> {
        self.storage.get_undo_data(id)
    }
}

impl FlushableUtxoView for InMemoryStorageWrapper {
    fn batch_write(&mut self, utxos: ConsumedUtxoCache) -> Result<(), utxo::Error> {
        let mut db = UtxosDBMut::new(&mut self.storage);
        db.batch_write(utxos)
    }
}

impl TransactionVerifierStorageMut for InMemoryStorageWrapper {
    fn set_mainchain_tx_index(
        &mut self,
        tx_id: &OutPointSourceId,
        tx_index: &common::chain::TxMainChainIndex,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.storage
            .set_mainchain_tx_index(tx_id, tx_index)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn del_mainchain_tx_index(
        &mut self,
        tx_id: &OutPointSourceId,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.storage
            .del_mainchain_tx_index(tx_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn set_token_aux_data(
        &mut self,
        token_id: &TokenId,
        data: &TokenAuxiliaryData,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.storage
            .set_token_aux_data(token_id, data)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn del_token_aux_data(
        &mut self,
        token_id: &TokenId,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.storage
            .del_token_aux_data(token_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn set_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
        token_id: &TokenId,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.storage
            .set_token_id(issuance_tx_id, token_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn del_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.storage
            .del_token_id(issuance_tx_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn set_undo_data(
        &mut self,
        id: Id<Block>,
        undo: &utxo::BlockUndo,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.storage
            .set_undo_data(id, undo)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn del_undo_data(&mut self, id: Id<Block>) -> Result<(), TransactionVerifierStorageError> {
        self.storage.del_undo_data(id).map_err(TransactionVerifierStorageError::from)
    }

    fn set_mempool_undo_data(
        &mut self,
        _undo: &utxo::BlockUndo,
    ) -> Result<(), TransactionVerifierStorageError> {
        panic!("Mempool info should not be written to storage")
    }

    fn del_mempool_undo_data(&mut self) -> Result<(), TransactionVerifierStorageError> {
        panic!("Mempool info should not be written to storage")
    }
}
