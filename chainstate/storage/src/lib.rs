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

use std::collections::{BTreeMap, BTreeSet};

use chainstate_types::{BlockIndex, EpochStorageRead, EpochStorageWrite};
use common::{
    chain::{
        block::{signed_block_header::SignedBlockHeader, BlockReward},
        config::{EpochIndex, MagicBytes},
        tokens::{TokenAuxiliaryData, TokenId},
        transaction::Transaction,
        AccountNonce, AccountType, Block, GenBlock,
    },
    primitives::{BlockHeight, Id},
};
use pos_accounting::{
    DeltaMergeUndo, PoSAccountingDeltaData, PoSAccountingStorageRead, PoSAccountingStorageWrite,
};
use tokens_accounting::{TokensAccountingStorageRead, TokensAccountingStorageWrite};
use utxo::{UtxosBlockUndo, UtxosStorageRead, UtxosStorageWrite};

pub use internal::{ChainstateStorageVersion, Store};

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
    UtxosStorageRead<Error = crate::Error>
    + PoSAccountingStorageRead<SealedStorageTag>
    + PoSAccountingStorageRead<TipStorageTag>
    + EpochStorageRead
    + TokensAccountingStorageRead<Error = crate::Error>
{
    // TODO: below (and in lots of other places too) Id is sometimes passes by ref and sometimes
    // by value. It's better to choose one "canonical" approach and use it everywhere.
    // Same applies to other "primitive" types, like BlockHeight (the latter, being 64 bit long,
    // should probably be passed by value even if we decide to pass Id by ref).

    /// Get storage version
    fn get_storage_version(&self) -> crate::Result<Option<ChainstateStorageVersion>>;

    /// Get magic bytes
    fn get_magic_bytes(&self) -> crate::Result<Option<MagicBytes>>;

    /// Get chain type name
    fn get_chain_type(&self) -> crate::Result<Option<String>>;

    /// Get the hash of the best block
    fn get_best_block_id(&self) -> crate::Result<Option<Id<GenBlock>>>;

    fn get_block_index(&self, block_id: &Id<Block>) -> crate::Result<Option<BlockIndex>>;

    fn get_block_reward(&self, block_index: &BlockIndex) -> crate::Result<Option<BlockReward>>;

    /// Get block by its hash
    fn get_block(&self, id: Id<Block>) -> crate::Result<Option<Block>>;

    /// Return true if the block exists in the db and false otherwise.
    /// This is cheaper than calling `get_block` and checking for `is_some`.
    fn block_exists(&self, id: Id<Block>) -> crate::Result<bool>;

    fn get_block_header(&self, id: Id<Block>) -> crate::Result<Option<SignedBlockHeader>>;

    /// Get the height below which reorgs should not be allowed.
    fn get_min_height_with_allowed_reorg(&self) -> crate::Result<Option<BlockHeight>>;

    /// Get mainchain block by its height
    fn get_block_id_by_height(&self, height: &BlockHeight) -> crate::Result<Option<Id<GenBlock>>>;

    fn get_undo_data(&self, id: Id<Block>) -> crate::Result<Option<UtxosBlockUndo>>;

    /// Get token creation tx
    fn get_token_aux_data(&self, token_id: &TokenId) -> crate::Result<Option<TokenAuxiliaryData>>;

    /// Get token id by id of the creation tx
    fn get_token_id(&self, tx_id: &Id<Transaction>) -> crate::Result<Option<TokenId>>;

    /// Get block tree as height vs ids
    fn get_block_tree_by_height(
        &self,
        start_from: BlockHeight,
    ) -> crate::Result<BTreeMap<BlockHeight, Vec<Id<Block>>>>;

    /// Get tokens accounting undo for specific block
    fn get_tokens_accounting_undo(
        &self,
        id: Id<Block>,
    ) -> crate::Result<Option<tokens_accounting::BlockUndo>>;

    /// Get accounting undo for specific block
    fn get_pos_accounting_undo(
        &self,
        id: Id<Block>,
    ) -> crate::Result<Option<pos_accounting::BlockUndo>>;

    /// Get accounting delta for specific epoch
    fn get_accounting_epoch_delta(
        &self,
        epoch_index: EpochIndex,
    ) -> crate::Result<Option<PoSAccountingDeltaData>>;

    /// Get accounting undo delta for specific epoch
    fn get_accounting_epoch_undo_delta(
        &self,
        epoch_index: EpochIndex,
    ) -> crate::Result<Option<DeltaMergeUndo>>;

    /// Get nonce value for specific account
    fn get_account_nonce_count(&self, account: AccountType) -> crate::Result<Option<AccountNonce>>;

    /// Get all keys (block ids) from the block map. This is used in the chainstate's
    /// "heavy" consistency checks.
    fn get_block_map_keys(&self) -> crate::Result<BTreeSet<Id<Block>>>;
    /// Get the entire block index map as BTreeMap. This is used in the chainstate's
    /// "heavy" consistency checks.
    fn get_block_index_map(&self) -> crate::Result<BTreeMap<Id<Block>, BlockIndex>>;
    /// Get the entire mainchain-block-by-height map as BTreeMap. This is used in the chainstate's
    /// "heavy" consistency checks.
    fn get_block_by_height_map(&self) -> crate::Result<BTreeMap<BlockHeight, Id<GenBlock>>>;
}

/// Modifying operations on persistent blockchain data
pub trait BlockchainStorageWrite:
    BlockchainStorageRead
    + UtxosStorageWrite
    + PoSAccountingStorageWrite<SealedStorageTag>
    + PoSAccountingStorageWrite<TipStorageTag>
    + EpochStorageWrite
    + TokensAccountingStorageWrite
{
    /// Set storage version
    fn set_storage_version(&mut self, version: ChainstateStorageVersion) -> Result<()>;

    /// Set magic bytes
    fn set_magic_bytes(&mut self, bytes: &MagicBytes) -> Result<()>;

    /// Set chain type name
    fn set_chain_type(&mut self, chain: &str) -> Result<()>;

    /// Set the hash of the best block
    fn set_best_block_id(&mut self, id: &Id<GenBlock>) -> Result<()>;

    /// Set the block index
    fn set_block_index(&mut self, block_index: &BlockIndex) -> Result<()>;

    /// Remove block index from the database
    fn del_block_index(&mut self, block_id: Id<Block>) -> Result<()>;

    /// Add a new block into the database
    fn add_block(&mut self, block: &Block) -> Result<()>;

    /// Remove block from the database
    fn del_block(&mut self, id: Id<Block>) -> Result<()>;

    /// Set the height below which reorgs should not be allowed.
    fn set_min_height_with_allowed_reorg(&mut self, height: BlockHeight) -> crate::Result<()>;

    /// Set the mainchain block at given height to be given block.
    fn set_block_id_at_height(
        &mut self,
        height: &BlockHeight,
        block_id: &Id<GenBlock>,
    ) -> Result<()>;

    /// Remove block id from given mainchain height
    fn del_block_id_at_height(&mut self, height: &BlockHeight) -> Result<()>;

    fn set_undo_data(&mut self, id: Id<Block>, undo: &UtxosBlockUndo) -> Result<()>;
    fn del_undo_data(&mut self, id: Id<Block>) -> Result<()>;

    /// Set data associated with token issuance (and ACL changes in the future)
    fn set_token_aux_data(&mut self, token_id: &TokenId, data: &TokenAuxiliaryData) -> Result<()>;

    /// Remove token tx
    fn del_token_aux_data(&mut self, token_id: &TokenId) -> Result<()>;

    /// Binding Id of issuance tx with token id
    fn set_token_id(&mut self, issuance_tx_id: &Id<Transaction>, token_id: &TokenId) -> Result<()>;

    /// Remove token id
    fn del_token_id(&mut self, issuance_tx_id: &Id<Transaction>) -> Result<()>;

    /// Set tokens accounting undo data for specific block
    fn set_tokens_accounting_undo_data(
        &mut self,
        id: Id<Block>,
        undo: &tokens_accounting::BlockUndo,
    ) -> Result<()>;

    /// Remove tokens accounting undo data for specific block
    fn del_tokens_accounting_undo_data(&mut self, id: Id<Block>) -> Result<()>;

    /// Set accounting block undo data for specific block
    fn set_pos_accounting_undo_data(
        &mut self,
        id: Id<Block>,
        undo: &pos_accounting::BlockUndo,
    ) -> Result<()>;

    /// Remove accounting block undo data for specific block
    fn del_pos_accounting_undo_data(&mut self, id: Id<Block>) -> Result<()>;

    /// Set accounting delta for specific block
    fn set_accounting_epoch_delta(
        &mut self,
        epoch_index: EpochIndex,
        delta: &PoSAccountingDeltaData,
    ) -> Result<()>;

    /// Remove accounting delta for specific block
    fn del_accounting_epoch_delta(&mut self, epoch_index: EpochIndex) -> Result<()>;

    /// Set accounting undo for specific epoch
    fn set_accounting_epoch_undo_delta(
        &mut self,
        epoch_index: EpochIndex,
        undo: &DeltaMergeUndo,
    ) -> Result<()>;

    /// Remove accounting block undo data for specific block
    fn del_accounting_epoch_undo_delta(&mut self, epoch_index: EpochIndex) -> Result<()>;

    fn set_account_nonce_count(&mut self, account: AccountType, nonce: AccountNonce) -> Result<()>;
    fn del_account_nonce_count(&mut self, account: AccountType) -> Result<()>;
}

/// Operations on read-only transactions
pub trait TransactionRo: BlockchainStorageRead {
    /// Close the transaction
    fn close(self);
}

/// Operations on read-write transactions
pub trait TransactionRw: BlockchainStorageWrite {
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
    fn transaction_ro<'s: 't>(&'s self) -> Result<Self::TransactionRo>;

    /// Start a read-write transaction.
    fn transaction_rw<'s: 't>(&'s self, size: Option<usize>) -> Result<Self::TransactionRw>;
}

pub trait BlockchainStorage: for<'tx> Transactional<'tx> + Send {}
