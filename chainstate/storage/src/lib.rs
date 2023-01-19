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

//! Application-level interface for the persistent blockchain storage.

mod internal;
mod is_transaction_seal;
#[cfg(any(test, feature = "mock"))]
pub mod mock;
pub mod schema;

use std::collections::BTreeMap;

pub use internal::{utxo_db, Store};

use chainstate_types::BlockIndex;
use common::chain::block::BlockReward;
use common::chain::tokens::{TokenAuxiliaryData, TokenId};
use common::chain::transaction::{Transaction, TxMainChainIndex, TxMainChainPosition};
use common::chain::{Block, GenBlock, OutPointSourceId};
use common::primitives::{BlockHeight, Id};
use pos_accounting::{
    AccountingBlockUndo, PoSAccountingDeltaData, PoSAccountingStorageRead,
    PoSAccountingStorageWrite,
};
use utxo::{UtxosStorageRead, UtxosStorageWrite};

/// Possibly failing result of blockchain storage query
pub type Result<T> = chainstate_types::storage_result::Result<T>;
pub type Error = chainstate_types::storage_result::Error;

pub mod inmemory {
    pub type Store = super::Store<storage::inmemory::InMemory>;
}

pub struct TipStorageTag;
impl pos_accounting::StorageTag for TipStorageTag {}

pub struct SealedStorageTag;
impl pos_accounting::StorageTag for SealedStorageTag {}

/// Queries on persistent blockchain data
pub trait BlockchainStorageRead:
    UtxosStorageRead
    + PoSAccountingStorageRead<SealedStorageTag>
    + PoSAccountingStorageRead<TipStorageTag>
{
    /// Get storage version
    fn get_storage_version(&self) -> crate::Result<u32>;

    /// Get the hash of the best block
    fn get_best_block_id(&self) -> crate::Result<Option<Id<GenBlock>>>;

    fn get_block_index(&self, block_id: &Id<Block>) -> crate::Result<Option<BlockIndex>>;

    fn get_block_reward(&self, block_index: &BlockIndex) -> crate::Result<Option<BlockReward>>;

    /// Get block by its hash
    fn get_block(&self, id: Id<Block>) -> crate::Result<Option<Block>>;

    fn get_is_mainchain_tx_index_enabled(&self) -> crate::Result<Option<bool>>;

    /// Get outputs state for given transaction in the mainchain
    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> crate::Result<Option<TxMainChainIndex>>;

    /// Get transaction by block ID and position
    fn get_mainchain_tx_by_position(
        &self,
        tx_index: &TxMainChainPosition,
    ) -> crate::Result<Option<Transaction>>;

    /// Get mainchain block by its height
    fn get_block_id_by_height(&self, height: &BlockHeight) -> crate::Result<Option<Id<GenBlock>>>;

    /// Get token creation tx
    fn get_token_aux_data(&self, token_id: &TokenId) -> crate::Result<Option<TokenAuxiliaryData>>;

    /// Get token id by id of the creation tx
    fn get_token_id(&self, tx_id: &Id<Transaction>) -> crate::Result<Option<TokenId>>;

    /// Get block tree as height vs ids
    fn get_block_tree_by_height(&self) -> crate::Result<BTreeMap<BlockHeight, Vec<Id<Block>>>>;

    /// Get accounting undo for specific block
    fn get_accounting_undo(&self, id: Id<Block>) -> crate::Result<Option<AccountingBlockUndo>>;

    fn get_pre_seal_accounting_delta(
        &self,
        epoch_index: u64,
    ) -> crate::Result<Option<PoSAccountingDeltaData>>;

    fn get_pre_seal_accounting_delta_undo(
        &self,
        epoch_index: u64,
        id: Id<Block>,
    ) -> crate::Result<Option<pos_accounting::DeltaMergeUndo>>;
}

/// Modifying operations on persistent blockchain data
pub trait BlockchainStorageWrite:
    BlockchainStorageRead
    + UtxosStorageWrite
    + PoSAccountingStorageWrite<SealedStorageTag>
    + PoSAccountingStorageWrite<TipStorageTag>
{
    /// Set storage version
    fn set_storage_version(&mut self, version: u32) -> crate::Result<()>;

    /// Set the hash of the best block
    fn set_best_block_id(&mut self, id: &Id<GenBlock>) -> crate::Result<()>;

    // Set the block index
    fn set_block_index(&mut self, block_index: &BlockIndex) -> crate::Result<()>;

    /// Add a new block into the database
    fn add_block(&mut self, block: &Block) -> crate::Result<()>;

    /// Remove block from the database
    fn del_block(&mut self, id: Id<Block>) -> crate::Result<()>;

    /// Change tx indexing state flag
    fn set_is_mainchain_tx_index_enabled(&mut self, enabled: bool) -> crate::Result<()>;

    /// Set state of the outputs of given transaction
    fn set_mainchain_tx_index(
        &mut self,
        tx_id: &OutPointSourceId,
        tx_index: &TxMainChainIndex,
    ) -> crate::Result<()>;

    /// Delete outputs state index associated with given transaction
    fn del_mainchain_tx_index(&mut self, tx_id: &OutPointSourceId) -> crate::Result<()>;

    /// Set the mainchain block at given height to be given block.
    fn set_block_id_at_height(
        &mut self,
        height: &BlockHeight,
        block_id: &Id<GenBlock>,
    ) -> crate::Result<()>;

    /// Remove block id from given mainchain height
    fn del_block_id_at_height(&mut self, height: &BlockHeight) -> crate::Result<()>;

    /// Set data associated with token issuance (and ACL changes in the future)
    fn set_token_aux_data(
        &mut self,
        token_id: &TokenId,
        data: &TokenAuxiliaryData,
    ) -> crate::Result<()>;

    // Remove token tx
    fn del_token_aux_data(&mut self, token_id: &TokenId) -> crate::Result<()>;

    // Binding Id of issuance tx with token id
    fn set_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
        token_id: &TokenId,
    ) -> crate::Result<()>;

    // Remove token id
    fn del_token_id(&mut self, issuance_tx_id: &Id<Transaction>) -> crate::Result<()>;

    // Set accounting block undo data for specific block
    fn set_accounting_undo_data(
        &mut self,
        id: Id<Block>,
        undo: &AccountingBlockUndo,
    ) -> crate::Result<()>;

    // Remove accounting block undo data for specific block
    fn del_accounting_undo_data(&mut self, id: Id<Block>) -> crate::Result<()>;

    fn set_pre_seal_accounting_delta(
        &mut self,
        epoch_index: u64,
        delta: &PoSAccountingDeltaData,
    ) -> crate::Result<()>;

    fn del_pre_seal_accounting_delta(&mut self, epoch_index: u64) -> crate::Result<()>;

    fn set_pre_seal_accounting_delta_undo(
        &mut self,
        epoch_index: u64,
        id: Id<Block>,
        delta: &pos_accounting::DeltaMergeUndo,
    ) -> crate::Result<()>;

    fn del_pre_seal_accounting_delta_undo(
        &mut self,
        epoch_index: u64,
        id: Id<Block>,
    ) -> crate::Result<()>;
    fn del_epoch_pre_seal_accounting_delta_undo(&mut self, epoch_index: u64) -> crate::Result<()>;
}

/// Marker trait for types where read/write operations are run in a transaction
pub trait IsTransaction: is_transaction_seal::Seal {}

/// Operations on read-only transactions
pub trait TransactionRo: BlockchainStorageRead + IsTransaction {
    /// Close the transaction
    fn close(self);
}

/// Operations on read-write transactions
pub trait TransactionRw: BlockchainStorageWrite + IsTransaction {
    /// Abort the transaction
    fn abort(self);

    /// Commit the transaction
    fn commit(self) -> crate::Result<()>;
}

/// Support for transactions over blockchain storage
pub trait Transactional<'t> {
    /// Associated read-only transaction type.
    type TransactionRo: TransactionRo + 't;

    /// Associated read-write transaction type.
    type TransactionRw: TransactionRw + 't;

    /// Start a read-only transaction.
    fn transaction_ro<'s: 't>(&'s self) -> crate::Result<Self::TransactionRo>;

    /// Start a read-write transaction.
    fn transaction_rw<'s: 't>(&'s self, size: Option<usize>) -> crate::Result<Self::TransactionRw>;
}

pub trait BlockchainStorage: BlockchainStorageWrite + for<'tx> Transactional<'tx> + Send {}
