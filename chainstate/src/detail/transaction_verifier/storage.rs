use chainstate_types::{storage_result, GenBlockIndex};
use common::{
    chain::{
        tokens::{TokenAuxiliaryData, TokenId},
        Block, GenBlock, OutPointSourceId, Transaction, TxMainChainIndex,
    },
    primitives::{BlockHeight, Id},
};
use thiserror::Error;
use utxo::{BlockUndo, UtxosStorageRead, UtxosStorageWrite};

use crate::TokensError;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum TransactionVerifierStorageError {
    #[error("Gen block index not found")]
    GenBlockIndexRetrievalFailed(Id<GenBlock>),
    #[error("Failed to persist state: {0}")]
    StatePersistenceError(#[from] chainstate_types::StatePersistenceError),
    #[error("Failed to persist state: {0}")]
    GetAncestorError(#[from] chainstate_types::GetAncestorError),
}

pub trait TransactionVerifierStorageRef: UtxosStorageRead {
    fn get_token_id_from_issuance_tx(
        &self,
        tx_id: Id<Transaction>,
    ) -> Result<Option<TokenId>, TransactionVerifierStorageError>;

    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, storage_result::Error>;

    fn get_ancestor(
        &self,
        block_index: &GenBlockIndex,
        target_height: BlockHeight,
    ) -> Result<GenBlockIndex, TransactionVerifierStorageError>;

    fn get_undo_data(
        &self,
        id: Id<Block>,
    ) -> Result<Option<BlockUndo>, TransactionVerifierStorageError>;

    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<TxMainChainIndex>, TransactionVerifierStorageError>;

    fn get_token_aux_data(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<TokenAuxiliaryData>, TokensError>;
}

pub trait TransactionVerifierStorageMut: TransactionVerifierStorageRef + UtxosStorageWrite {
    fn set_mainchain_tx_index(
        &mut self,
        tx_id: &OutPointSourceId,
        tx_index: &TxMainChainIndex,
    ) -> Result<(), TransactionVerifierStorageError>;

    fn del_mainchain_tx_index(
        &mut self,
        tx_id: &OutPointSourceId,
    ) -> Result<(), TransactionVerifierStorageError>;

    fn set_token_aux_data(
        &mut self,
        token_id: &TokenId,
        data: &TokenAuxiliaryData,
    ) -> Result<(), TransactionVerifierStorageError>;

    fn del_token_aux_data(
        &mut self,
        token_id: &TokenId,
    ) -> Result<(), TransactionVerifierStorageError>;

    fn set_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
        token_id: &TokenId,
    ) -> Result<(), TransactionVerifierStorageError>;

    fn del_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
    ) -> Result<(), TransactionVerifierStorageError>;
}
