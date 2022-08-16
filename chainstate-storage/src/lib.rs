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

use chainstate_types::BlockIndex;
use common::chain::block::BlockReward;
use common::chain::tokens::TokenId;
use common::chain::transaction::{Transaction, TxMainChainIndex, TxMainChainPosition};
use common::chain::OutPointSourceId;
use common::chain::{Block, GenBlock};
use common::primitives::{BlockHeight, Id};
use storage::traits;
use utxo::utxo_storage::{UtxosStorageRead, UtxosStorageWrite};

mod internal;
#[cfg(any(test, feature = "mock"))]
pub mod mock;

pub use internal::{utxo_db, Store};
pub use storage::transaction::{TransactionRo, TransactionRw};

/// Possibly failing result of blockchain storage query
pub type Result<T> = chainstate_types::storage_result::Result<T>;
pub type Error = chainstate_types::storage_result::Error;

pub mod inmemory {
    use crate::internal;
    pub type Store = internal::Store<storage::inmemory::Store<internal::Schema>>;
}

/// Queries on persistent blockchain data
pub trait BlockchainStorageRead: UtxosStorageRead {
    /// Get storage version
    fn get_storage_version(&self) -> crate::Result<u32>;

    /// Get the hash of the best block
    fn get_best_block_id(&self) -> crate::Result<Option<Id<GenBlock>>>;

    fn get_block_index(&self, block_id: &Id<Block>) -> crate::Result<Option<BlockIndex>>;

    fn get_block_reward(&self, block_index: &BlockIndex) -> crate::Result<Option<BlockReward>>;

    /// Get block by its hash
    fn get_block(&self, id: Id<Block>) -> crate::Result<Option<Block>>;

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
    fn get_token_tx(&self, token_id: TokenId) -> crate::Result<Option<Id<Transaction>>>;
}

/// Modifying operations on persistent blockchain data
pub trait BlockchainStorageWrite: BlockchainStorageRead + UtxosStorageWrite {
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

    /// Set token creation tx
    fn set_token_tx(&mut self, token_id: TokenId, tx_id: Id<Transaction>) -> crate::Result<()>;

    // Remove token tx
    fn del_token_tx(&mut self, token_id: TokenId) -> crate::Result<()>;
}

/// Support for transactions over blockchain storage
pub trait Transactional<'t> {
    /// Associated read-only transaction type.
    type TransactionRo: traits::TransactionRo<Error = crate::Error> + BlockchainStorageRead + 't;

    /// Associated read-write transaction type.
    type TransactionRw: traits::TransactionRw<Error = crate::Error> + BlockchainStorageWrite + 't;

    /// Start a read-only transaction.
    fn transaction_ro<'s: 't>(&'s self) -> Self::TransactionRo;

    /// Start a read-write transaction.
    fn transaction_rw<'s: 't>(&'s self) -> Self::TransactionRw;
}

pub trait BlockchainStorage: BlockchainStorageWrite + for<'tx> Transactional<'tx> + Send {}
