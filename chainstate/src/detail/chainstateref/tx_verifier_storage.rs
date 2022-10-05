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

use crate::detail::{
    chainstateref::ChainstateRef,
    orphan_blocks::OrphanBlocks,
    transaction_verifier::storage::{
        TransactionVerifierStorageError, TransactionVerifierStorageMut,
        TransactionVerifierStorageRef,
    },
};
use chainstate_storage::{BlockchainStorageRead, BlockchainStorageWrite};
use chainstate_types::{storage_result, GenBlockIndex};
use common::{
    chain::{
        tokens::{TokenAuxiliaryData, TokenId},
        Block, ChainConfig, GenBlock, GenBlockId, OutPointSourceId, Transaction,
    },
    primitives::{BlockHeight, Id},
};
use utxo::{ConsumedUtxoCache, FlushableUtxoView, UtxosDBMut, UtxosStorageRead};

impl<'a, S: BlockchainStorageRead, O: OrphanBlocks> TransactionVerifierStorageRef
    for ChainstateRef<'a, S, O>
{
    fn get_token_id_from_issuance_tx(
        &self,
        tx_id: Id<Transaction>,
    ) -> Result<Option<TokenId>, TransactionVerifierStorageError> {
        self.db_tx.get_token_id(&tx_id).map_err(TransactionVerifierStorageError::from)
    }

    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, storage_result::Error> {
        gen_block_index_getter(&self.db_tx, self.chain_config, block_id)
    }

    fn get_ancestor(
        &self,
        block_index: &GenBlockIndex,
        target_height: BlockHeight,
    ) -> Result<GenBlockIndex, TransactionVerifierStorageError> {
        self.get_ancestor(block_index, target_height)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<common::chain::TxMainChainIndex>, TransactionVerifierStorageError> {
        self.db_tx
            .get_mainchain_tx_index(tx_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn get_token_aux_data(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<TokenAuxiliaryData>, TransactionVerifierStorageError> {
        self.db_tx
            .get_token_aux_data(token_id)
            .map_err(TransactionVerifierStorageError::from)
    }
}

// TODO: this function is a duplicate of one in chainstate-types; the cause for this is that BlockchainStorageRead causes a circular dependencies
// BlockchainStorageRead should probably be moved out of storage
pub fn gen_block_index_getter<S: BlockchainStorageRead>(
    db_tx: &S,
    chain_config: &ChainConfig,
    block_id: &Id<GenBlock>,
) -> Result<Option<GenBlockIndex>, storage_result::Error> {
    match block_id.classify(chain_config) {
        GenBlockId::Genesis(_id) => Ok(Some(GenBlockIndex::Genesis(Arc::clone(
            chain_config.genesis_block(),
        )))),
        GenBlockId::Block(id) => db_tx.get_block_index(&id).map(|b| b.map(GenBlockIndex::Block)),
    }
}

impl<'a, S: BlockchainStorageRead, O: OrphanBlocks> UtxosStorageRead for ChainstateRef<'a, S, O> {
    fn get_utxo(
        &self,
        outpoint: &common::chain::OutPoint,
    ) -> Result<Option<utxo::Utxo>, chainstate_types::storage_result::Error> {
        self.db_tx.get_utxo(outpoint)
    }

    fn get_best_block_for_utxos(
        &self,
    ) -> Result<Option<Id<GenBlock>>, chainstate_types::storage_result::Error> {
        self.db_tx.get_best_block_for_utxos()
    }

    fn get_undo_data(
        &self,
        id: Id<Block>,
    ) -> Result<Option<utxo::BlockUndo>, chainstate_types::storage_result::Error> {
        self.db_tx.get_undo_data(id)
    }
}

impl<'a, S: BlockchainStorageWrite, O: OrphanBlocks> FlushableUtxoView for ChainstateRef<'a, S, O> {
    fn batch_write(&mut self, utxos: ConsumedUtxoCache) -> Result<(), utxo::Error> {
        let mut db = UtxosDBMut::new(&mut self.db_tx);
        db.batch_write(utxos)
    }
}

impl<'a, S: BlockchainStorageWrite, O: OrphanBlocks> TransactionVerifierStorageMut
    for ChainstateRef<'a, S, O>
{
    fn set_mainchain_tx_index(
        &mut self,
        tx_id: &OutPointSourceId,
        tx_index: &common::chain::TxMainChainIndex,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.db_tx
            .set_mainchain_tx_index(tx_id, tx_index)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn del_mainchain_tx_index(
        &mut self,
        tx_id: &OutPointSourceId,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.db_tx
            .del_mainchain_tx_index(tx_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn set_token_aux_data(
        &mut self,
        token_id: &TokenId,
        data: &TokenAuxiliaryData,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.db_tx
            .set_token_aux_data(token_id, data)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn del_token_aux_data(
        &mut self,
        token_id: &TokenId,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.db_tx
            .del_token_aux_data(token_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn set_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
        token_id: &TokenId,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.db_tx
            .set_token_id(issuance_tx_id, token_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn del_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.db_tx
            .del_token_id(issuance_tx_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn set_undo_data(
        &mut self,
        id: Id<Block>,
        undo: &utxo::BlockUndo,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.db_tx
            .set_undo_data(id, undo)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn del_undo_data(&mut self, id: Id<Block>) -> Result<(), TransactionVerifierStorageError> {
        self.db_tx.del_undo_data(id).map_err(TransactionVerifierStorageError::from)
    }
}
