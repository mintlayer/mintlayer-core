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

use std::{collections::BTreeSet, sync::Arc};

use chainstate_storage::{BlockchainStorageRead, BlockchainStorageWrite, TransactionRw};
use chainstate_types::{get_skip_height, BlockIndex, GenBlockIndex, PropertyQueryError};
use common::{
    chain::{
        block::{
            calculate_tx_merkle_root, calculate_witness_merkle_root, BlockHeader, BlockReward,
        },
        Block, ChainConfig, GenBlock, GenBlockId, OutPointSourceId,
    },
    primitives::{BlockDistance, BlockHeight, Id, Idable},
    Uint256,
};
use consensus::{BlockIndexHandle, TransactionIndexHandle};
use logging::log;
use utils::ensure;
use utxo::{UtxosDB, UtxosView};

use super::{median_time::calculate_median_time_past, time_getter::TimeGetterFn};
use crate::{BlockError, BlockSource, ChainstateConfig};

use super::{
    orphan_blocks::{OrphanBlocks, OrphanBlocksMut},
    transaction_verifier::{BlockTransactableRef, TransactionVerifier},
    BlockSizeError, CheckBlockError, CheckBlockTransactionsError, OrphanCheckError,
};

pub(crate) struct ChainstateRef<'a, S, O> {
    chain_config: &'a ChainConfig,
    _chainstate_config: &'a ChainstateConfig,
    db_tx: S,
    orphan_blocks: O,
    time_getter: &'a TimeGetterFn,
}

impl<'a, S: BlockchainStorageRead, O: OrphanBlocks> BlockIndexHandle for ChainstateRef<'a, S, O> {
    fn get_block_index(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError> {
        self.get_block_index(block_id)
    }

    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
        self.get_gen_block_index(block_id)
    }

    fn get_ancestor(
        &self,
        block_index: &BlockIndex,
        ancestor_height: BlockHeight,
    ) -> Result<GenBlockIndex, PropertyQueryError> {
        self.get_ancestor(&GenBlockIndex::Block(block_index.clone()), ancestor_height)
    }

    fn get_block_reward(
        &self,
        block_index: &BlockIndex,
    ) -> Result<Option<BlockReward>, PropertyQueryError> {
        self.get_block_reward(block_index)
    }
}

impl<'a, S: BlockchainStorageRead, O: OrphanBlocks> TransactionIndexHandle
    for ChainstateRef<'a, S, O>
{
    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<common::chain::TxMainChainIndex>, PropertyQueryError> {
        self.get_mainchain_tx_index(tx_id)
    }

    fn get_mainchain_tx_by_position(
        &self,
        tx_index: &common::chain::TxMainChainPosition,
    ) -> Result<Option<common::chain::Transaction>, PropertyQueryError> {
        self.get_mainchain_tx_by_position(tx_index)
    }
}

impl<'a, S: TransactionRw<Error = chainstate_storage::Error>, O> ChainstateRef<'a, S, O> {
    pub fn commit_db_tx(self) -> chainstate_storage::Result<()> {
        self.db_tx.commit()
    }
}

impl<'a, S: BlockchainStorageRead, O: OrphanBlocks> ChainstateRef<'a, S, O> {
    pub fn new_rw(
        chain_config: &'a ChainConfig,
        chainstate_config: &'a ChainstateConfig,
        db_tx: S,
        orphan_blocks: O,
        time_getter: &'a TimeGetterFn,
    ) -> ChainstateRef<'a, S, O> {
        ChainstateRef {
            chain_config,
            _chainstate_config: chainstate_config,
            db_tx,
            orphan_blocks,
            time_getter,
        }
    }

    pub fn new_ro(
        chain_config: &'a ChainConfig,
        chainstate_config: &'a ChainstateConfig,
        db_tx: S,
        orphan_blocks: O,
        time_getter: &'a TimeGetterFn,
    ) -> ChainstateRef<'a, S, O> {
        ChainstateRef {
            chain_config,
            _chainstate_config: chainstate_config,
            db_tx,
            orphan_blocks,
            time_getter,
        }
    }

    pub fn current_time(&self) -> std::time::Duration {
        (self.time_getter)()
    }

    pub fn get_best_block_id(&self) -> Result<Id<GenBlock>, PropertyQueryError> {
        self.db_tx
            .get_best_block_id()
            .map_err(PropertyQueryError::from)
            .map(|bid| bid.expect("Best block ID not initialized"))
    }

    pub fn get_block_index(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError> {
        log::trace!("Loading block index of id: {}", block_id);
        self.db_tx.get_block_index(block_id).map_err(PropertyQueryError::from)
    }

    pub fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
        match block_id.classify(self.chain_config) {
            GenBlockId::Genesis(_id) => Ok(Some(GenBlockIndex::Genesis(Arc::clone(
                self.chain_config.genesis_block(),
            )))),
            GenBlockId::Block(id) => self.get_block_index(&id).map(|b| b.map(GenBlockIndex::Block)),
        }
    }

    pub fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<common::chain::TxMainChainIndex>, PropertyQueryError> {
        log::trace!("Loading transaction index of id: {:?}", tx_id);
        self.db_tx.get_mainchain_tx_index(tx_id).map_err(PropertyQueryError::from)
    }

    fn get_mainchain_tx_by_position(
        &self,
        tx_index: &common::chain::TxMainChainPosition,
    ) -> Result<Option<common::chain::Transaction>, PropertyQueryError> {
        log::trace!("Loading transaction by pos: {:?}", tx_index);
        self.db_tx
            .get_mainchain_tx_by_position(tx_index)
            .map_err(PropertyQueryError::from)
    }

    pub fn get_block_id_by_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, PropertyQueryError> {
        self.db_tx.get_block_id_by_height(height).map_err(PropertyQueryError::from)
    }

    pub fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, PropertyQueryError> {
        self.db_tx.get_block(block_id).map_err(PropertyQueryError::from)
    }

    pub fn is_block_in_main_chain(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<bool, PropertyQueryError> {
        let ht = match self.get_block_height_in_main_chain(block_id)? {
            None => return Ok(false),
            Some(ht) => ht,
        };
        let bid = self.get_block_id_by_height(&ht)?;
        Ok(bid == Some(*block_id))
    }

    /// Allow to read from storage the previous block and return itself BlockIndex
    fn get_previous_block_index(
        &self,
        block_index: &BlockIndex,
    ) -> Result<GenBlockIndex, PropertyQueryError> {
        let prev_block_id = block_index.prev_block_id();
        self.get_gen_block_index(prev_block_id)?
            .ok_or(PropertyQueryError::PrevBlockIndexNotFound(*prev_block_id))
    }

    pub fn get_ancestor(
        &self,
        block_index: &GenBlockIndex,
        target_height: BlockHeight,
    ) -> Result<GenBlockIndex, PropertyQueryError> {
        if target_height > block_index.block_height() {
            return Err(PropertyQueryError::InvalidAncestorHeight {
                block_height: block_index.block_height(),
                ancestor_height: target_height,
            });
        }

        let mut height_walk = block_index.block_height();
        let mut block_index_walk = block_index.clone();
        loop {
            assert!(height_walk >= target_height, "Skipped too much");
            if height_walk == target_height {
                break Ok(block_index_walk);
            }
            let cur_block_index = match block_index_walk {
                GenBlockIndex::Genesis(_) => break Ok(block_index_walk),
                GenBlockIndex::Block(idx) => idx,
            };

            let ancestor = cur_block_index.some_ancestor();

            let height_walk_prev =
                height_walk.prev_height().expect("Can never fail because prev is zero at worst");
            let height_skip = get_skip_height(height_walk);
            let height_skip_prev = get_skip_height(height_walk_prev);

            // prepare the booleans for the check
            let at_target = height_skip == target_height;
            let still_not_there = height_skip > target_height;
            let too_close = height_skip_prev.next_height().next_height() < height_skip;
            let prev_too_close = height_skip_prev >= target_height;

            if at_target || (still_not_there && !(too_close && prev_too_close)) {
                block_index_walk = self
                    .get_gen_block_index(ancestor)?
                    .expect("Block index of ancestor must exist, since id exists");
                height_walk = height_skip;
            } else {
                block_index_walk = self.get_previous_block_index(&cur_block_index)?;
                height_walk = height_walk_prev;
            }
        }
    }

    #[allow(unused)]
    pub fn last_common_ancestor(
        &self,
        first_block_index: &GenBlockIndex,
        second_block_index: &GenBlockIndex,
    ) -> Result<GenBlockIndex, PropertyQueryError> {
        let mut first_block_index = first_block_index.clone();
        let mut second_block_index = second_block_index.clone();
        match first_block_index.block_height().cmp(&second_block_index.block_height()) {
            std::cmp::Ordering::Greater => {
                first_block_index =
                    self.get_ancestor(&first_block_index, second_block_index.block_height())?;
            }
            std::cmp::Ordering::Less => {
                second_block_index =
                    self.get_ancestor(&second_block_index, first_block_index.block_height())?;
            }
            std::cmp::Ordering::Equal => {}
        }

        loop {
            match (&first_block_index, &second_block_index) {
                _ if first_block_index.block_id() == second_block_index.block_id() => {
                    break Ok(first_block_index)
                }
                (GenBlockIndex::Block(first_blkidx), GenBlockIndex::Block(second_blkidx)) => {
                    first_block_index = self.get_previous_block_index(first_blkidx)?;
                    second_block_index = self.get_previous_block_index(second_blkidx)?;
                }
                _ => panic!("Chain iteration not in lockstep"),
            }
        }
    }

    pub fn get_best_block_index(&self) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
        self.get_gen_block_index(&self.get_best_block_id()?)
    }

    pub fn get_header_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<BlockHeader>, PropertyQueryError> {
        let id = self
            .get_block_id_by_height(height)?
            .ok_or(PropertyQueryError::BlockForHeightNotFound(*height))?;
        let id = id
            .classify(self.chain_config)
            .chain_block_id()
            .ok_or(PropertyQueryError::GenesisHeaderRequested)?;
        Ok(self.get_block_index(&id)?.map(|block_index| block_index.into_block_header()))
    }

    pub fn get_block_reward(
        &self,
        block_index: &BlockIndex,
    ) -> Result<Option<BlockReward>, PropertyQueryError> {
        Ok(self.db_tx.get_block_reward(block_index)?)
    }

    pub fn get_block_height_in_main_chain(
        &self,
        id: &Id<GenBlock>,
    ) -> Result<Option<BlockHeight>, PropertyQueryError> {
        let id = match id.classify(self.chain_config) {
            GenBlockId::Block(id) => id,
            GenBlockId::Genesis(_) => return Ok(Some(BlockHeight::zero())),
        };
        let block_index = self.get_block_index(&id)?;
        let block_index = block_index.ok_or(PropertyQueryError::BlockNotFound(id))?;
        if block_index.block_id() == &id {
            Ok(Some(block_index.block_height()))
        } else {
            Ok(None)
        }
    }

    // Get indexes for a new longest chain
    fn get_new_chain(
        &self,
        new_tip_block_index: &BlockIndex,
    ) -> Result<Vec<BlockIndex>, PropertyQueryError> {
        let mut result = Vec::new();
        let mut block_index = new_tip_block_index.clone();
        while !self.is_block_in_main_chain(&(*block_index.block_id()).into())? {
            result.push(block_index.clone());
            block_index = match self.get_previous_block_index(&block_index)? {
                GenBlockIndex::Genesis(_) => break,
                GenBlockIndex::Block(blkidx) => blkidx,
            }
        }
        result.reverse();
        debug_assert!(!result.is_empty()); // there has to always be at least one new block
        Ok(result)
    }

    fn check_block_index(&self, block_index: &BlockIndex) -> Result<(), BlockError> {
        // BlockIndex is already known or block exists
        if self.db_tx.get_block_index(block_index.block_id())?.is_some() {
            return Err(BlockError::BlockAlreadyExists(*block_index.block_id()));
        }
        // TODO: Will be expanded
        Ok(())
    }

    fn check_block_detail(&self, block: &Block) -> Result<(), CheckBlockError> {
        // MerkleTree root
        let merkle_tree_root = block.merkle_root();
        calculate_tx_merkle_root(block.body()).map_or(
            Err(CheckBlockError::MerkleRootMismatch),
            |merkle_tree| {
                ensure!(
                    merkle_tree_root == merkle_tree,
                    CheckBlockError::MerkleRootMismatch
                );
                Ok(())
            },
        )?;

        // Witness merkle root
        let witness_merkle_root = block.witness_merkle_root();
        calculate_witness_merkle_root(block.body()).map_or(
            Err(CheckBlockError::WitnessMerkleRootMismatch),
            |witness_merkle| {
                ensure!(
                    witness_merkle_root == witness_merkle,
                    CheckBlockError::WitnessMerkleRootMismatch,
                );
                Ok(())
            },
        )?;

        let prev_block_id = block.prev_block_id();
        let median_time_past = calculate_median_time_past(self, &prev_block_id);
        ensure!(
            block.timestamp() >= median_time_past,
            CheckBlockError::BlockTimeOrderInvalid,
        );

        let max_future_offset = self.chain_config.max_future_block_time_offset();
        let current_time = self.current_time();
        let block_timestamp = block.timestamp();
        ensure!(
            block_timestamp.as_duration_since_epoch() <= current_time + *max_future_offset,
            CheckBlockError::BlockFromTheFuture,
        );

        self.check_transactions(block)
            .map_err(CheckBlockError::CheckTransactionFailed)?;

        self.check_block_size(block).map_err(CheckBlockError::BlockSizeError)?;

        Ok(())
    }

    fn check_block_size(&self, block: &Block) -> Result<(), BlockSizeError> {
        let block_size = block.block_size();

        ensure!(
            block_size.size_from_header() <= self.chain_config.max_block_header_size(),
            BlockSizeError::Header(
                block_size.size_from_header(),
                self.chain_config.max_block_header_size()
            )
        );

        ensure!(
            block_size.size_from_txs() <= self.chain_config.max_block_size_from_txs(),
            BlockSizeError::SizeOfTxs(
                block_size.size_from_txs(),
                self.chain_config.max_block_size_from_txs()
            )
        );

        ensure!(
            block_size.size_from_smart_contracts()
                <= self.chain_config.max_block_size_from_smart_contracts(),
            BlockSizeError::SizeOfSmartContracts(
                block_size.size_from_smart_contracts(),
                self.chain_config.max_block_size_from_smart_contracts()
            )
        );

        Ok(())
    }

    fn check_transactions(&self, block: &Block) -> Result<(), CheckBlockTransactionsError> {
        // check for duplicate inputs (see CVE-2018-17144)
        {
            let mut block_inputs = BTreeSet::new();
            for tx in block.transactions() {
                let mut tx_inputs = BTreeSet::new();
                for input in tx.inputs() {
                    ensure!(
                        tx_inputs.insert(input.outpoint()),
                        CheckBlockTransactionsError::DuplicateInputInTransaction(
                            tx.get_id(),
                            block.get_id()
                        )
                    );
                    ensure!(
                        block_inputs.insert(input.outpoint()),
                        CheckBlockTransactionsError::DuplicateInputInBlock(block.get_id())
                    );
                }
            }
        }

        {
            // check duplicate transactions
            let mut txs_ids = BTreeSet::new();
            for tx in block.transactions() {
                let tx_id = tx.get_id();
                let already_in_tx_id = txs_ids.get(&tx_id);
                match already_in_tx_id {
                    Some(_) => {
                        return Err(CheckBlockTransactionsError::DuplicatedTransactionInBlock(
                            tx_id,
                            block.get_id(),
                        ))
                    }
                    None => txs_ids.insert(tx_id),
                };
            }
        }

        Ok(())
    }

    fn get_block_from_index(&self, block_index: &BlockIndex) -> Result<Option<Block>, BlockError> {
        Ok(self.db_tx.get_block(*block_index.block_id())?)
    }

    pub fn check_block(&self, block: &Block) -> Result<(), CheckBlockError> {
        consensus::validate_consensus(self.chain_config, block.header(), self)
            .map_err(CheckBlockError::ConsensusVerificationFailed)?;
        self.check_block_detail(block)?;
        Ok(())
    }

    fn get_block_proof(&self, block: &Block) -> Result<Uint256, BlockError> {
        block
            .header()
            .consensus_data()
            .get_block_proof()
            .ok_or_else(|| BlockError::BlockProofCalculationError(block.get_id()))
    }

    fn make_cache_with_connected_transactions(
        &'a self,
        utxo_view: &'a impl UtxosView,
        block: &Block,
        spend_height: &BlockHeight,
        blockreward_maturity: &BlockDistance,
    ) -> Result<TransactionVerifier<S>, BlockError> {
        // The comparison for timelock is done with median_time_past based on BIP-113, i.e., the median time instead of the block timestamp
        let median_time_past = calculate_median_time_past(self, &block.prev_block_id());

        let mut tx_verifier =
            TransactionVerifier::new(&self.db_tx, utxo_view.derive_cache(), self.chain_config);

        let block_subsidy = self.chain_config.block_subsidy_at_height(spend_height);
        tx_verifier.check_block_reward(block, block_subsidy)?;

        tx_verifier.connect_transaction(
            BlockTransactableRef::BlockReward(block),
            spend_height,
            &median_time_past,
            blockreward_maturity,
        )?;

        for (tx_num, _tx) in block.transactions().iter().enumerate() {
            tx_verifier.connect_transaction(
                BlockTransactableRef::Transaction(block, tx_num),
                spend_height,
                &median_time_past,
                blockreward_maturity,
            )?;
        }

        Ok(tx_verifier)
    }

    fn make_cache_with_disconnected_transactions(
        &'a self,
        utxo_view: &'a impl UtxosView,
        block: &Block,
    ) -> Result<TransactionVerifier<S>, BlockError> {
        let mut tx_verifier =
            TransactionVerifier::new(&self.db_tx, utxo_view.derive_cache(), self.chain_config);
        block.transactions().iter().enumerate().try_for_each(|(tx_num, _tx)| {
            tx_verifier.disconnect_transaction(BlockTransactableRef::Transaction(block, tx_num))
        })?;
        tx_verifier.disconnect_transaction(BlockTransactableRef::BlockReward(block))?;
        Ok(tx_verifier)
    }
}

impl<'a, S: BlockchainStorageWrite, O: OrphanBlocksMut> ChainstateRef<'a, S, O> {
    pub fn check_legitimate_orphan(
        &mut self,
        block_source: BlockSource,
        block: Block,
    ) -> Result<Block, OrphanCheckError> {
        let prev_block_id = block.prev_block_id();

        let block_index_found = self
            .get_gen_block_index(&prev_block_id)
            .map_err(OrphanCheckError::PrevBlockIndexNotFound)?
            .is_some();

        if block_source == BlockSource::Local && !block_index_found {
            self.new_orphan_block(block)?;
            return Err(OrphanCheckError::LocalOrphan);
        }
        Ok(block)
    }

    fn disconnect_until(
        &mut self,
        to_disconnect: &BlockIndex,
        last_to_remain_connected: &Id<GenBlock>,
    ) -> Result<(), BlockError> {
        let mut to_disconnect = GenBlockIndex::Block(to_disconnect.clone());
        while to_disconnect.block_id() != *last_to_remain_connected {
            let to_disconnect_block = match to_disconnect {
                GenBlockIndex::Genesis(_) => panic!("Attempt to disconnect genesis"),
                GenBlockIndex::Block(block_index) => block_index,
            };
            to_disconnect = self.disconnect_tip(Some(to_disconnect_block.block_id()))?;
        }
        Ok(())
    }

    fn reorganize(
        &mut self,
        best_block_id: &Id<GenBlock>,
        new_block_index: &BlockIndex,
    ) -> Result<(), BlockError> {
        let new_chain = self.get_new_chain(new_block_index).map_err(|e| {
            BlockError::InvariantErrorFailedToFindNewChainPath(
                *new_block_index.block_id(),
                *best_block_id,
                e,
            )
        })?;

        let common_ancestor_id = {
            let err = "This vector cannot be empty since there is at least one block to connect";
            let first_block = &new_chain.first().expect(err);
            &first_block.prev_block_id()
        };

        // Disconnect the current chain if it is not a genesis
        if let GenBlockId::Block(best_block_id) = best_block_id.classify(self.chain_config) {
            let mainchain_tip = self
                .get_block_index(&best_block_id)
                .map_err(BlockError::BestBlockLoadError)?
                .expect("Can't get block index. Inconsistent DB");

            // Disconnect blocks
            self.disconnect_until(&mainchain_tip, common_ancestor_id)?;
        }

        // Connect the new chain
        for block_index in new_chain {
            self.connect_tip(&block_index)?;
        }

        Ok(())
    }

    fn connect_transactions(
        &mut self,
        block: &Block,
        spend_height: &BlockHeight,
        blockreward_maturity: &BlockDistance,
    ) -> Result<(), BlockError> {
        let utxo_db = UtxosDB::new(&self.db_tx);
        let connected_txs = self.make_cache_with_connected_transactions(
            &utxo_db,
            block,
            spend_height,
            blockreward_maturity,
        )?;

        let consumed = connected_txs.consume()?;
        TransactionVerifier::flush_to_storage(&mut self.db_tx, consumed)?;

        Ok(())
    }

    fn disconnect_transactions(&mut self, block: &Block) -> Result<(), BlockError> {
        let utxo_db = UtxosDB::new(&self.db_tx);
        let cached_inputs = self.make_cache_with_disconnected_transactions(&utxo_db, block)?;
        let cached_inputs = cached_inputs.consume()?;
        TransactionVerifier::flush_to_storage(&mut self.db_tx, cached_inputs)?;

        Ok(())
    }

    // Connect new block
    fn connect_tip(&mut self, new_tip_block_index: &BlockIndex) -> Result<(), BlockError> {
        let best_block_id = self.get_best_block_id().map_err(BlockError::BestBlockLoadError)?;
        utils::ensure!(
            &best_block_id == new_tip_block_index.prev_block_id(),
            BlockError::InvariantErrorInvalidTip,
        );
        let block = self.get_block_from_index(new_tip_block_index)?.expect("Inconsistent DB");

        self.connect_transactions(
            &block,
            &new_tip_block_index.block_height(),
            self.chain_config.blockreward_maturity(),
        )?;

        self.db_tx.set_block_id_at_height(
            &new_tip_block_index.block_height(),
            &(*new_tip_block_index.block_id()).into(),
        )?;
        self.db_tx.set_best_block_id(&(*new_tip_block_index.block_id()).into())?;
        Ok(())
    }

    /// Does a read-modify-write operation on the database and disconnects a block
    /// by unsetting the `next` pointer.
    /// Returns the previous block (the last block in the main-chain)
    fn disconnect_tip(
        &mut self,
        expected_tip_block_id: Option<&Id<Block>>,
    ) -> Result<GenBlockIndex, BlockError> {
        let best_block_id = self
            .get_best_block_id()
            .expect("Best block not initialized")
            .classify(self.chain_config)
            .chain_block_id()
            .expect("Cannot disconnect genesis");

        // Optionally, we can double-check that the tip is what we're disconnecting
        if let Some(expected_tip_block_id) = expected_tip_block_id {
            debug_assert_eq!(expected_tip_block_id, &best_block_id);
        }

        let block_index = self
            .get_block_index(&best_block_id)
            .expect("Database error on retrieving current best block index")
            .expect("Best block index not present in the database");
        let block = self.get_block_from_index(&block_index)?.expect("Inconsistent DB");
        // Disconnect transactions
        self.disconnect_transactions(&block)?;
        self.db_tx.set_best_block_id(block_index.prev_block_id())?;
        // Disconnect block
        self.db_tx.del_block_id_at_height(&block_index.block_height())?;

        let prev_block_index = self
            .get_previous_block_index(&block_index)
            .expect("Previous block index retrieval failed");
        Ok(prev_block_index)
    }

    pub fn activate_best_chain(
        &mut self,
        new_block_index: BlockIndex,
        best_block_id: Id<GenBlock>,
    ) -> Result<Option<BlockIndex>, BlockError> {
        // Chain trust is higher than the best block
        let current_best_block_index = self
            .get_gen_block_index(&best_block_id)
            .map_err(BlockError::BestBlockLoadError)?
            .expect("Inconsistent DB");

        if new_block_index.chain_trust() > current_best_block_index.chain_trust() {
            self.reorganize(&best_block_id, &new_block_index)?;
            return Ok(Some(new_block_index));
        }

        Ok(None)
    }

    fn add_to_block_index(&mut self, block: &Block) -> Result<BlockIndex, BlockError> {
        match self.db_tx.get_block_index(&block.get_id()).map_err(BlockError::from)? {
            // this is not an error, because it's valid to have the header but not the whole block
            Some(bi) => return Ok(bi),
            None => (),
        }

        let prev_block_index = self
            .get_gen_block_index(&block.prev_block_id())
            .map_err(BlockError::BestBlockLoadError)?
            .ok_or(BlockError::PrevBlockNotFound)?;

        // Set the block height
        let height = prev_block_index.block_height().next_height();

        let some_ancestor = {
            let skip_ht = get_skip_height(height);
            let err = |_| panic!("Ancestor retrieval failed for block: {}", block.get_id());
            self.get_ancestor(&prev_block_index, skip_ht).unwrap_or_else(err).block_id()
        };

        // Set Time Max
        let time_max = std::cmp::max(prev_block_index.chain_timestamps_max(), block.timestamp());

        // Set Chain Trust
        let chain_trust = *prev_block_index.chain_trust() + self.get_block_proof(block)?;
        let block_index = BlockIndex::new(block, chain_trust, some_ancestor, height, time_max);
        Ok(block_index)
    }

    pub fn accept_block(&mut self, block: &Block) -> Result<BlockIndex, BlockError> {
        let block_index = self.add_to_block_index(block)?;
        match self.db_tx.get_block(block.get_id()).map_err(BlockError::from)? {
            Some(_) => return Err(BlockError::BlockAlreadyExists(block.get_id())),
            None => (),
        }
        self.check_block_index(&block_index)?;
        self.db_tx.set_block_index(&block_index).map_err(BlockError::from)?;
        self.db_tx.add_block(block).map_err(BlockError::from)?;
        Ok(block_index)
    }

    /// Mark new block as an orphan
    fn new_orphan_block(&mut self, block: Block) -> Result<(), OrphanCheckError> {
        match self.orphan_blocks.add_block(block) {
            Ok(_) => Ok(()),
            Err(err) => err.into(),
        }
    }
}
