use chainstate_types::{storage_result, GenBlockIndex};
use common::{
    chain::{
        tokens::{TokenAuxiliaryData, TokenId},
        Block, GenBlock, OutPoint, OutPointSourceId, Transaction, TxMainChainIndex,
    },
    primitives::{BlockHeight, Id},
};
use utxo::{UtxosStorageRead, UtxosView};

use super::{
    storage::{TransactionVerifierStorageError, TransactionVerifierStorageRef},
    TransactionVerifier,
};

impl<'a, S: TransactionVerifierStorageRef> TransactionVerifierStorageRef
    for TransactionVerifier<'a, S>
{
    fn get_token_id_from_issuance_tx(
        &self,
        tx_id: Id<Transaction>,
    ) -> Result<Option<TokenId>, TransactionVerifierStorageError> {
        match self.token_issuance_cache.txid_from_issuance().get(&tx_id) {
            Some(v) => return Ok(Some(*v)),
            None => (),
        };
        self.db_tx.get_token_id_from_issuance_tx(tx_id)
    }

    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, storage_result::Error> {
        self.db_tx.get_gen_block_index(block_id)
    }

    fn get_ancestor(
        &self,
        block_index: &GenBlockIndex,
        target_height: BlockHeight,
    ) -> Result<GenBlockIndex, TransactionVerifierStorageError> {
        self.db_tx.get_ancestor(block_index, target_height)
    }

    fn get_undo_data(
        &self,
        _id: Id<Block>,
    ) -> Result<Option<utxo::BlockUndo>, TransactionVerifierStorageError> {
        // match self.utxo_block_undo.get(&id) {
        //     Some(v) => return Ok(Some(v.clone())),
        //     None => (),
        // };
        // TransactionVerifierStorageRef::get_undo_data(self.db_tx, id)
        todo!()
    }

    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<TxMainChainIndex>, TransactionVerifierStorageError> {
        match self.tx_index_cache.get_from_cached(tx_id) {
            Some(v) => match v {
                super::cached_operation::CachedInputsOperation::Write(idx) => {
                    return Ok(Some(idx.clone()))
                }
                super::cached_operation::CachedInputsOperation::Read(idx) => {
                    return Ok(Some(idx.clone()))
                }
                super::cached_operation::CachedInputsOperation::Erase => return Ok(None),
            },
            None => (),
        };
        self.db_tx.get_mainchain_tx_index(tx_id)
    }

    fn get_token_aux_data(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<TokenAuxiliaryData>, crate::TokensError> {
        match self.token_issuance_cache.data().get(token_id) {
            Some(v) => match v {
                super::token_issuance_cache::CachedTokensOperation::Write(t) => {
                    return Ok(Some(t.clone()))
                }
                super::token_issuance_cache::CachedTokensOperation::Read(t) => {
                    return Ok(Some(t.clone()))
                }
                super::token_issuance_cache::CachedTokensOperation::Erase(_) => return Ok(None),
            },
            None => (),
        }
        self.db_tx.get_token_aux_data(token_id)
    }
}

impl<'a, S> UtxosStorageRead for TransactionVerifier<'a, S> {
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<utxo::Utxo>, storage_result::Error> {
        Ok(self.utxo_cache.utxo(outpoint))
    }

    fn get_best_block_for_utxos(&self) -> Result<Option<Id<GenBlock>>, storage_result::Error> {
        Ok(Some(self.utxo_cache.best_block_hash()))
    }

    fn get_undo_data(
        &self,
        _id: Id<Block>,
    ) -> Result<Option<utxo::BlockUndo>, storage_result::Error> {
        todo!()
    }
}
