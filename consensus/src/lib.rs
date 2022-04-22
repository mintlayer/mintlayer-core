// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): S. Afach, A. Sinitsyn

use crate::orphan_blocks::{OrphanAddError, OrphanBlocksPool};
use blockchain_storage::BlockchainStorageRead;
use blockchain_storage::BlockchainStorageWrite;
use blockchain_storage::TransactionRw;
use blockchain_storage::Transactional;
use common::chain::block::block_index::BlockIndex;
use common::chain::block::{calculate_tx_merkle_root, calculate_witness_merkle_root, Block};
use common::chain::calculate_tx_index_from_block;
use common::chain::config::ChainConfig;
use common::chain::Spender;
use common::chain::{OutPointSourceId, Transaction};
use common::chain::{SpendError, TxMainChainIndexError};
use common::primitives::BlockDistance;
use common::primitives::{time, Amount, BlockHeight, Id, Idable};
use std::collections::BTreeSet;
use thiserror::Error;
mod orphan_blocks;
use parity_scale_codec::Encode;

mod pow;

type PeerId = u32;
type TxRw<'a> = <blockchain_storage::Store as Transactional<'a>>::TransactionRw;

mod spend_cache;

use spend_cache::CachedInputs;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum BlockError {
    #[error("Unknown error")]
    Unknown,
    #[error("Orphan")]
    Orphan,
    #[error("Invalid block height `{0}`")]
    InvalidBlockHeight(BlockHeight),
    #[error("The previous block invalid")]
    PrevBlockInvalid,
    #[error("The storage cause failure `{0}`")]
    StorageFailure(blockchain_storage::Error),
    #[error("The block not found")]
    NotFound,
    #[error("Invalid block source")]
    InvalidBlockSource,
    #[error("Duplicate transaction found in block")]
    DuplicatedTransactionInBlock,
    #[error("Outputs already in the inputs cache")]
    OutputAlreadyPresentInInputsCache,
    #[error("Output is not found in the cache or database")]
    MissingOutputOrSpent,
    #[error("Output index out of range")]
    OutputIndexOutOfRange,
    #[error("Output was erased in a previous step (possible in reorgs with no cache flushing)")]
    MissingOutputOrSpentOutputErased,
    #[error("Double-spend attempt")]
    DoubleSpendAttempt(Spender),
    #[error("Block disconnect already-unspent (invaraint broken)")]
    InvariantBrokenAlreadyUnspent,
    #[error("Source block index for block reward output not found")]
    InvariantBrokenSourceBlockIndexNotFound,
    #[error("Block distance calculation for maturity failed")]
    BlockHeightArithmeticError,
    #[error("Block reward spent immaturely")]
    ImmatureBlockRewardSpend,
    #[error("Invalid output count")]
    InvalidOutputCount,
    #[error("Input was cached, but could not be found")]
    PreviouslyCachedInputNotFound,
    #[error("Input was cached, but it is erased")]
    PreviouslyCachedInputWasErased,
    #[error("Transaction index found but transaction not found")]
    InvariantErrorTransactionCouldNotBeLoaded,
    #[error("Input addition error")]
    InputAdditionError,
    #[error("Output addition error")]
    OutputAdditionError,
    #[error("Attempt to print money (total inputs: `{0:?}` vs total outputs `{1:?}`")]
    AttemptToPrintMoney(Amount, Amount),
    #[error("Duplicate input in transaction")]
    DuplicateInputInTransaction(Id<Transaction>),
    #[error("Duplicate input in block")]
    DuplicateInputInBlock(Id<Block>),
    #[error("Transaction number `{0}` does not exist in block `{1:?}`")]
    TxNumWrongInBlock(usize, Id<Block>),
    #[error("Serialization invariant failed for block `{0:?}`")]
    SerializationInvariantError(Id<Block>),
    #[error("Unexpected numeric type conversion error `{0:?}`")]
    InternalNumTypeConversionError(Id<Block>),
    // To be expanded
}

impl From<blockchain_storage::Error> for BlockError {
    fn from(_err: blockchain_storage::Error) -> Self {
        // On storage level called err.recoverable(), if an error is unrecoverable then it calls panic!
        // We don't need to cause panic here
        BlockError::Unknown
    }
}

impl From<SpendError> for BlockError {
    fn from(err: SpendError) -> Self {
        match err {
            SpendError::AlreadySpent(spender) => BlockError::DoubleSpendAttempt(spender),
            SpendError::AlreadyUnspent => BlockError::InvariantBrokenAlreadyUnspent,
            SpendError::OutOfRange => BlockError::OutputIndexOutOfRange,
        }
    }
}

impl From<TxMainChainIndexError> for BlockError {
    fn from(err: TxMainChainIndexError) -> Self {
        match err {
            TxMainChainIndexError::InvalidOutputCount => BlockError::InvalidOutputCount,
            TxMainChainIndexError::SerializationInvariantError(block_id) => {
                BlockError::SerializationInvariantError(block_id)
            }
            TxMainChainIndexError::InvalidTxNumberForBlock(tx_num, block_id) => {
                BlockError::TxNumWrongInBlock(tx_num, block_id)
            }
            TxMainChainIndexError::InternalNumTypeConversionError(block_id) => {
                BlockError::InternalNumTypeConversionError(block_id)
            }
        }
    }
}

// DSA allows us to have blocks up to 1mb
const MAX_BLOCK_WEIGHT: usize = 1_048_576;

// TODO: ISSUE #129 - https://github.com/mintlayer/mintlayer-core/issues/129
pub struct Consensus {
    chain_config: ChainConfig,
    blockchain_storage: blockchain_storage::Store,
    orphan_blocks: OrphanBlocksPool,
}

#[derive(Copy, Clone, Eq, Debug, PartialEq)]
pub enum BlockSource {
    Peer(PeerId),
    Local,
}

impl Consensus {
    fn make_db_tx(&mut self) -> ConsensusRef {
        let db_tx = self.blockchain_storage.transaction_rw();
        ConsensusRef {
            chain_config: &self.chain_config,
            db_tx,
            orphan_blocks: &mut self.orphan_blocks,
        }
    }

    pub fn new(chain_config: ChainConfig, blockchain_storage: blockchain_storage::Store) -> Self {
        Self {
            chain_config,
            blockchain_storage,
            orphan_blocks: OrphanBlocksPool::new_default(),
        }
    }

    pub fn process_block(
        &mut self,
        block: Block,
        block_source: BlockSource,
    ) -> Result<Option<BlockIndex>, BlockError> {
        let mut consensus_ref = self.make_db_tx();
        // Reasonable reduce amount of calls to DB
        let best_block_id = consensus_ref.db_tx.get_best_block_id().map_err(BlockError::from)?;
        // TODO: this seems to require block index, which doesn't seem to be the case in bitcoin, as otherwise orphans can't be checked
        consensus_ref.check_block(&block, block_source)?;
        let block_index = consensus_ref.accept_block(&block);
        if block_index == Err(BlockError::Orphan) {
            if BlockSource::Local == block_source {
                // TODO: Discuss with Sam about it later (orphans should be searched for children of any newly accepted block)
                consensus_ref.new_orphan_block(block)?;
            }
            return Err(BlockError::Orphan);
        }
        let result = consensus_ref.activate_best_chain(block_index?, best_block_id)?;
        consensus_ref.commit_db_tx().expect("Committing transactions to DB failed");
        Ok(result)
    }
}

struct ConsensusRef<'a> {
    chain_config: &'a ChainConfig,
    // TODO: make this generic over Rw and Ro
    db_tx: TxRw<'a>,
    orphan_blocks: &'a mut OrphanBlocksPool,
}

impl<'a> ConsensusRef<'a> {
    fn commit_db_tx(self) -> blockchain_storage::Result<()> {
        self.db_tx.commit()
    }

    /// Allow to read from storage the previous block and return itself BlockIndex
    fn get_previous_block_index(&self, block_index: &BlockIndex) -> Result<BlockIndex, BlockError> {
        let prev_block_id = block_index.get_prev_block_id().as_ref().ok_or(BlockError::NotFound)?;
        self.db_tx.get_block_index(prev_block_id)?.ok_or(BlockError::NotFound)
    }

    // Get indexes for a new longest chain
    fn get_new_chain(
        &self,
        new_tip_block_index: &BlockIndex,
    ) -> Result<Vec<BlockIndex>, BlockError> {
        let mut result = Vec::new();
        let mut block_index = new_tip_block_index.clone();
        while !self.is_block_in_main_chain(&block_index)? {
            result.push(block_index.clone());
            block_index = self.get_previous_block_index(&block_index)?;
        }
        result.reverse();
        debug_assert!(!result.is_empty()); // there has to always be at least one new block
        Ok(result)
    }

    fn disconnect_until(
        &mut self,
        to_disconnect: &BlockIndex,
        last_to_remain_connected: &Id<Block>,
    ) -> Result<(), BlockError> {
        if to_disconnect.get_block_id() == last_to_remain_connected {
            return Ok(());
        }

        let current_mainchain_tip = self.disconnect_tip(Some(to_disconnect.get_block_id()))?;
        self.disconnect_until(&current_mainchain_tip, last_to_remain_connected)
    }

    fn reorganize(
        &mut self,
        best_block_id: &Id<Block>,
        new_block_index: &BlockIndex,
    ) -> Result<(), BlockError> {
        let new_chain = self.get_new_chain(new_block_index)?;

        let common_ancestor_id = {
            let err = "This vector cannot be empty since there is at least one block to connect";
            let first_block = &new_chain.first().expect(err);
            &first_block.get_prev_block_id().as_ref().expect("This can never be genesis")
        };

        // Disconnect the current chain if it is not a genesis
        {
            let mainchain_tip = self
                .db_tx
                .get_block_index(best_block_id)?
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

    fn connect_transactions_inner(
        &self,
        block: &Block,
        spend_height: &BlockHeight,
        blockreward_maturity: &BlockDistance,
    ) -> Result<CachedInputs, BlockError> {
        let mut cached_inputs = CachedInputs::new(&self.db_tx);
        for (tx_num, _tx) in block.transactions().iter().enumerate() {
            cached_inputs.spend(block, tx_num, spend_height, blockreward_maturity)?;
        }
        Ok(cached_inputs)
    }

    fn connect_transactions(
        &mut self,
        block: &Block,
        spend_height: &BlockHeight,
        blockreward_maturity: &BlockDistance,
    ) -> Result<(), BlockError> {
        let cached_inputs =
            self.connect_transactions_inner(block, spend_height, blockreward_maturity)?;
        let cached_inputs = cached_inputs.consume()?;

        CachedInputs::flush_to_storage(&mut self.db_tx, cached_inputs)?;
        Ok(())
    }

    fn disconnect_transactions_inner(
        &mut self,
        transactions: &[Transaction],
    ) -> Result<CachedInputs, BlockError> {
        let mut cached_inputs = CachedInputs::new(&self.db_tx);
        transactions.iter().try_for_each(|tx| cached_inputs.unspend(tx))?;
        Ok(cached_inputs)
    }

    fn disconnect_transactions(&mut self, transactions: &[Transaction]) -> Result<(), BlockError> {
        let cached_inputs = self.disconnect_transactions_inner(transactions)?;
        let cached_inputs = cached_inputs.consume()?;

        CachedInputs::flush_to_storage(&mut self.db_tx, cached_inputs)?;
        Ok(())
    }

    fn check_tx_outputs(&self, transactions: &[Transaction]) -> Result<(), BlockError> {
        for tx in transactions {
            for _output in tx.get_outputs() {
                // TODO: Check tx outputs to prevent the overwriting of the transaction
            }
        }
        Ok(())
    }

    fn connect_genesis_transactions(&mut self, block: &Block) -> Result<(), BlockError> {
        for (num, tx) in block.transactions().iter().enumerate() {
            self.db_tx.set_mainchain_tx_index(
                &OutPointSourceId::from(tx.get_id()),
                &calculate_tx_index_from_block(block, num)?,
            )?;
        }
        Ok(())
    }

    // Connect new block
    fn connect_tip(&mut self, new_tip_block_index: &BlockIndex) -> Result<(), BlockError> {
        if &self.db_tx.get_best_block_id()? != new_tip_block_index.get_prev_block_id() {
            return Err(BlockError::Unknown);
        }
        let block = self.get_block_from_index(new_tip_block_index)?.expect("Inconsistent DB");
        self.check_tx_outputs(block.transactions())?;

        if block.is_genesis(self.chain_config) {
            self.connect_genesis_transactions(&block)?
        } else {
            self.connect_transactions(
                &block,
                &new_tip_block_index.get_block_height(),
                self.chain_config.get_blockreward_maturity(),
            )?;
        }

        self.db_tx.set_block_id_at_height(
            &new_tip_block_index.get_block_height(),
            new_tip_block_index.get_block_id(),
        )?;
        self.db_tx.set_block_index(new_tip_block_index)?;
        self.db_tx.set_best_block_id(new_tip_block_index.get_block_id())?;
        Ok(())
    }

    /// Does a read-modify-write operation on the database and disconnects a block
    /// by unsetting the `next` pointer.
    /// Returns the previous block (the last block in the main-chain)
    fn disconnect_tip(
        &mut self,
        expected_tip_block_id: Option<&Id<Block>>,
    ) -> Result<BlockIndex, BlockError> {
        let best_block_id =
            self.db_tx.get_best_block_id().ok().flatten().expect("Only fails at genesis");

        // Optionally, we can double-check that the tip is what we're discconnecting
        match expected_tip_block_id {
            None => {}
            Some(expected_tip_block_id) => debug_assert!(expected_tip_block_id == &best_block_id),
        }

        let block_index = self
            .db_tx
            .get_block_index(&best_block_id)
            .expect("Database error on retrieving current best block index")
            .expect("Also only genesis fails at this");
        let block = self.get_block_from_index(&block_index)?.expect("Inconsistent DB");
        // Disconnect transactions
        self.disconnect_transactions(block.transactions())?;
        self.db_tx.set_best_block_id(
            block_index.get_prev_block_id().as_ref().ok_or(BlockError::Unknown)?,
        )?;
        // Disconnect block
        self.db_tx.del_block_id_at_height(&block_index.get_block_height())?;

        let prev_block_index = self.get_previous_block_index(&block_index)?;
        Ok(prev_block_index)
    }

    fn try_connect_genesis_block(
        &mut self,
        genesis_block_index: &BlockIndex,
        best_block_id: &Option<Id<Block>>,
    ) -> Result<Option<BlockIndex>, BlockError> {
        if best_block_id.is_none() && genesis_block_index.is_genesis(self.chain_config) {
            self.connect_tip(genesis_block_index)?;
            return Ok(Some(genesis_block_index.clone()));
        }
        Ok(None)
    }

    fn activate_best_chain(
        &mut self,
        new_block_index: BlockIndex,
        best_block_id: Option<Id<Block>>,
    ) -> Result<Option<BlockIndex>, BlockError> {
        let connected_genesis = self.try_connect_genesis_block(&new_block_index, &best_block_id)?;
        if connected_genesis.is_some() {
            return Ok(connected_genesis);
        }

        let best_block_id = best_block_id.expect("Best block must be set at this point");
        // Chain trust is higher than the best block
        let current_best_block_index = self
            .db_tx
            .get_block_index(&best_block_id)
            .map_err(BlockError::from)?
            .expect("Inconsistent DB");

        if new_block_index.get_chain_trust() > current_best_block_index.get_chain_trust() {
            self.reorganize(&best_block_id, &new_block_index)?;
            return Ok(Some(new_block_index));
        }

        Ok(None)
    }

    fn get_block_proof(&self, _block: &Block) -> u128 {
        //TODO: We have to make correct one
        1
    }

    fn add_to_block_index(&mut self, block: &Block) -> Result<BlockIndex, BlockError> {
        let prev_block_index = if block.is_genesis(self.chain_config) {
            // Genesis case. We should use then_some when stabilized feature(bool_to_option)
            None
        } else {
            block.prev_block_id().map_or(Err(BlockError::Orphan), |prev_block| {
                self.db_tx.get_block_index(&prev_block).map_err(BlockError::from)
            })?
        };
        // Set the block height
        let height = prev_block_index.as_ref().map_or(BlockHeight::zero(), |prev_block_index| {
            prev_block_index.get_block_height().next_height()
        });

        // Set Time Max
        let time_max = prev_block_index.as_ref().map_or(block.block_time(), |prev_block_index| {
            std::cmp::max(prev_block_index.get_block_time_max(), block.block_time())
        });

        // Set Chain Trust
        let chain_trust = prev_block_index
            .map_or(0, |prev_block_index| prev_block_index.get_chain_trust())
            + self.get_block_proof(block);
        let block_index = BlockIndex::new(block, chain_trust, height, time_max);
        Ok(block_index)
    }

    fn accept_block(&mut self, block: &Block) -> Result<BlockIndex, BlockError> {
        let block_index = self.add_to_block_index(block)?;
        self.check_block_index(&block_index)?;
        self.db_tx.set_block_index(&block_index).map_err(BlockError::from)?;
        self.db_tx.add_block(block).map_err(BlockError::from)?;
        Ok(block_index)
    }

    fn check_block_index(&self, block_index: &BlockIndex) -> Result<(), BlockError> {
        // BlockIndex is already known or block exists
        if self.db_tx.get_block_index(block_index.get_block_id())?.is_some() {
            return Err(BlockError::Unknown);
        }
        // TODO: Will be expanded
        Ok(())
    }

    fn check_block_detail(
        &self,
        block: &Block,
        block_source: BlockSource,
    ) -> Result<(), BlockError> {
        // Allows the previous block to be None only if the block hash is genesis
        if !block.is_genesis(self.chain_config) && block.prev_block_id().is_none() {
            return Err(BlockError::Unknown);
        }

        // MerkleTree root
        let merkle_tree_root = block.merkle_root();
        calculate_tx_merkle_root(block.transactions()).map_or(
            Err(BlockError::Unknown),
            |merkle_tree| {
                if merkle_tree_root != merkle_tree {
                    Err(BlockError::Unknown)
                } else {
                    Ok(())
                }
            },
        )?;

        // Witness merkle root
        let witness_merkle_root = block.witness_merkle_root();
        calculate_witness_merkle_root(block.transactions()).map_or(
            Err(BlockError::Unknown),
            |witness_merkle| {
                if witness_merkle_root != witness_merkle {
                    Err(BlockError::Unknown)
                } else {
                    Ok(())
                }
            },
        )?;

        match &block.prev_block_id() {
            Some(block_id) => {
                let previous_block = self
                    .db_tx
                    .get_block_index(&Id::<Block>::new(&block_id.get()))?
                    .ok_or(BlockError::Orphan)?;
                // Time
                let block_time = block.block_time();
                if previous_block.get_block_time() > block_time {
                    return Err(BlockError::Unknown);
                }
                if i64::from(block_time) > time::get() {
                    return Err(BlockError::Unknown);
                }
            }
            None => {
                // This is only for genesis, AND should never come from a peer
                if block_source != BlockSource::Local {
                    return Err(BlockError::InvalidBlockSource);
                };
            }
        }

        self.check_transactions(block)?;
        Ok(())
    }

    fn check_consensus(&self, block: &Block) -> Result<(), BlockError> {
        let _consensus_data = block.consensus_data();
        // TODO: PoW is not in master at the moment =(
        Ok(())
    }

    fn check_transactions(&self, block: &Block) -> Result<(), BlockError> {
        // check for duplicate inputs (see CVE-2018-17144)
        {
            let mut block_inputs = BTreeSet::new();
            for tx in block.transactions() {
                let mut tx_inputs = BTreeSet::new();
                for input in tx.get_inputs() {
                    if !block_inputs.insert(input.get_outpoint()) {
                        return Err(BlockError::DuplicateInputInBlock(block.get_id()));
                    }
                    if !tx_inputs.insert(input.get_outpoint()) {
                        return Err(BlockError::DuplicateInputInTransaction(tx.get_id()));
                    }
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
                    Some(_) => return Err(BlockError::DuplicatedTransactionInBlock),
                    None => txs_ids.insert(tx_id),
                };
            }
        }

        //TODO: Size limits
        if block.encoded_size() > MAX_BLOCK_WEIGHT {
            return Err(BlockError::Unknown);
        }
        //TODO: Check signatures will be added when BLS is ready
        Ok(())
    }

    fn check_block(&self, block: &Block, block_source: BlockSource) -> Result<(), BlockError> {
        self.check_consensus(block)?;
        self.check_block_detail(block, block_source)?;
        Ok(())
    }

    fn is_block_in_main_chain(&self, block_index: &BlockIndex) -> Result<bool, BlockError> {
        let height = block_index.get_block_height();
        let id_at_height = self.db_tx.get_block_id_by_height(&height).map_err(BlockError::from)?;
        match id_at_height {
            Some(id) => Ok(id == *block_index.get_block_id()),
            None => Ok(false),
        }
    }

    /// Mark new block as an orphan
    fn new_orphan_block(&mut self, block: Block) -> Result<(), BlockError> {
        // It can't be a genesis block
        assert!(!block.is_genesis(self.chain_config));
        self.orphan_blocks.add_block(block).map_err(|err| match err {
            OrphanAddError::BlockAlreadyInOrphanList(_) => BlockError::Orphan,
        })?;
        Ok(())
    }

    fn get_block_from_index(&self, block_index: &BlockIndex) -> Result<Option<Block>, BlockError> {
        Ok(self.db_tx.get_block(block_index.get_block_id().clone())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blockchain_storage::Store;
    use common::address::Address;
    use common::chain::block::{Block, ConsensusData};
    use common::chain::config::create_mainnet;

    use common::chain::{Destination, OutputSpentState, Transaction, TxInput, TxOutput};
    use common::primitives::H256;
    use common::primitives::{Amount, Id};
    use rand::prelude::*;

    pub(crate) const ERR_BEST_BLOCK_NOT_FOUND: &str = "Best block not found";
    pub(crate) const ERR_STORAGE_FAIL: &str = "Storage failure";
    pub(crate) const ERR_CREATE_BLOCK_FAIL: &str = "Creating block caused fail";
    pub(crate) const ERR_CREATE_TX_FAIL: &str = "Creating tx caused fail";

    fn generate_random_h256(g: &mut impl rand::Rng) -> H256 {
        let mut bytes = [0u8; 32];
        g.fill_bytes(&mut bytes);
        H256::from(bytes)
    }

    fn generate_random_bytes(g: &mut impl rand::Rng, length: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.resize(length, 0);
        g.fill_bytes(&mut bytes);
        bytes
    }

    fn generate_random_invalid_input(g: &mut impl rand::Rng) -> TxInput {
        let witness_size = g.next_u32();
        let witness = generate_random_bytes(g, (1 + witness_size % 1000) as usize);
        let outpoint = if g.next_u32() % 2 == 0 {
            OutPointSourceId::Transaction(Id::new(&generate_random_h256(g)))
        } else {
            OutPointSourceId::BlockReward(Id::new(&generate_random_h256(g)))
        };

        TxInput::new(outpoint, g.next_u32(), witness)
    }

    fn generate_random_invalid_output(g: &mut impl rand::Rng) -> TxOutput {
        let config = create_mainnet();

        let addr =
            Address::new(&config, generate_random_bytes(g, 20)).expect("Failed to create address");

        TxOutput::new(
            Amount::from_atoms(g.next_u64() as u128),
            Destination::Address(addr),
        )
    }

    fn generate_random_invalid_transaction(rng: &mut impl rand::Rng) -> Transaction {
        let inputs = {
            let input_count = 1 + (rng.next_u32() as usize) % 10;
            (0..input_count)
                .into_iter()
                .map(|_| generate_random_invalid_input(rng))
                .collect::<Vec<_>>()
        };

        let outputs = {
            let output_count = 1 + (rng.next_u32() as usize) % 10;
            (0..output_count)
                .into_iter()
                .map(|_| generate_random_invalid_output(rng))
                .collect::<Vec<_>>()
        };

        let flags = rng.next_u32();
        let lock_time = rng.next_u32();

        Transaction::new(flags, inputs, outputs, lock_time).expect(ERR_CREATE_TX_FAIL)
    }

    fn generate_random_invalid_block() -> Block {
        let mut rng = rand::rngs::StdRng::from_entropy();

        let transactions = {
            let transaction_count = rng.next_u32() % 2000;
            (0..transaction_count)
                .into_iter()
                .map(|_| generate_random_invalid_transaction(&mut rng))
                .collect::<Vec<_>>()
        };
        let time = rng.next_u32();
        let prev_id = Some(Id::new(&generate_random_h256(&mut rng)));

        Block::new(transactions, prev_id, time, ConsensusData::None).expect(ERR_CREATE_BLOCK_FAIL)
    }

    fn setup_consensus() -> Consensus {
        let config = create_mainnet();
        let storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new(config.clone(), storage);

        // Process genesis
        let result = consensus.process_block(config.genesis_block().clone(), BlockSource::Local);
        assert!(result.is_ok());
        assert_eq!(
            consensus
                .blockchain_storage
                .get_best_block_id()
                .expect(ERR_BEST_BLOCK_NOT_FOUND),
            Some(config.genesis_block().get_id())
        );
        consensus
    }

    fn create_utxo_data(
        config: &ChainConfig,
        tx_id: &Id<Transaction>,
        index: usize,
        output: &TxOutput,
    ) -> Option<(TxInput, TxOutput)> {
        if output.get_value() > Amount::from_atoms(1) {
            // Random address receiver
            let mut rng = rand::thread_rng();
            let mut witness: Vec<u8> = (1..100).collect();
            witness.shuffle(&mut rng);
            let mut address: Vec<u8> = (1..22).collect();
            address.shuffle(&mut rng);
            let receiver = Address::new(config, address).expect("Failed to create address");
            Some((
                TxInput::new(
                    OutPointSourceId::Transaction(tx_id.clone()),
                    index as u32,
                    witness,
                ),
                TxOutput::new(
                    (output.get_value() - Amount::from_atoms(1)).unwrap(),
                    Destination::Address(receiver),
                ),
            ))
        } else {
            None
        }
    }

    fn produce_test_block(config: &ChainConfig, prev_block: &Block, orphan: bool) -> Block {
        // For each output we create a new input and output that will placed into a new block.
        // If value of original output is less than 1 then output will disappear in a new block.
        // Otherwise, value will be decreasing for 1.
        let (inputs, outputs): (Vec<TxInput>, Vec<TxOutput>) = prev_block
            .transactions()
            .iter()
            .flat_map(|tx| create_new_outputs(config, tx))
            .unzip();

        Block::new(
            vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
            if orphan {
                Some(Id::new(&H256::random()))
            } else {
                Some(Id::new(&prev_block.get_id().get()))
            },
            time::get() as u32,
            ConsensusData::None,
        )
        .expect(ERR_CREATE_BLOCK_FAIL)
    }

    fn create_new_outputs(config: &ChainConfig, tx: &Transaction) -> Vec<(TxInput, TxOutput)> {
        tx.get_outputs()
            .iter()
            .enumerate()
            .filter_map(move |(index, output)| {
                create_utxo_data(config, &tx.get_id(), index, output)
            })
            .collect::<Vec<(TxInput, TxOutput)>>()
    }

    #[test]
    fn test_indices_calculations() {
        let block = generate_random_invalid_block();
        let serialized_block = block.encode();
        let serialized_header = block.header().encode();
        let serialized_transactions = block.transactions().encode();
        assert_eq!(
            // +1 for the enum arm byte
            1 + serialized_header.len() + serialized_transactions.len(),
            serialized_block.len(),
        );
        // TODO: calculate block reward position
        for (tx_num, tx) in block.transactions().iter().enumerate() {
            let tx_index = calculate_tx_index_from_block(&block, tx_num).unwrap();
            assert!(!tx_index.all_outputs_spent());
            assert_eq!(tx_index.get_output_count(), tx.get_outputs().len() as u32);

            let pos = match tx_index.get_position() {
                common::chain::SpendablePosition::Transaction(pos) => pos,
                common::chain::SpendablePosition::BlockReward(_) => unreachable!(),
            };
            let tx_start_pos = pos.get_byte_offset_in_block() as usize;
            let tx_end_pos =
                pos.get_byte_offset_in_block() as usize + pos.get_serialized_size() as usize;
            let tx_serialized_in_block = &serialized_block[tx_start_pos..tx_end_pos];
            let tx_serialized = tx.encode();
            assert_eq!(tx_serialized_in_block, tx_serialized);

            // to ensure Vec comparison is correct since I'm a paranoid C++ dude, let's mess things up
            let tx_messed = tx_serialized.iter().map(|c| c.wrapping_add(1)).collect::<Vec<u8>>();
            assert!(tx_serialized_in_block != tx_messed);
        }
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn test_process_genesis_block_wrong_block_source() {
        common::concurrency::model(|| {
            // Genesis can't be from Peer, test it
            let config = create_mainnet();
            let storage = Store::new_empty().unwrap();
            let mut consensus = Consensus::new(config.clone(), storage);

            // process the genesis block
            let block_source = BlockSource::Peer(0);
            let result = consensus.process_block(config.genesis_block().clone(), block_source);
            assert_eq!(result, Err(BlockError::InvalidBlockSource));
        });
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn test_process_genesis_block() {
        common::concurrency::model(|| {
            // This test process only Genesis block
            let config = create_mainnet();
            let storage = Store::new_empty().unwrap();
            let mut consensus = Consensus::new(config.clone(), storage);

            // process the genesis block
            let block_source = BlockSource::Local;
            let block_index = consensus
                .process_block(config.genesis_block().clone(), block_source)
                .ok()
                .flatten()
                .unwrap();
            assert_eq!(
                consensus
                    .blockchain_storage
                    .get_best_block_id()
                    .expect(ERR_BEST_BLOCK_NOT_FOUND),
                Some(config.genesis_block().get_id())
            );
            assert_eq!(block_index.get_prev_block_id(), &None);
            assert_eq!(block_index.get_chain_trust(), 1);
            assert_eq!(block_index.get_block_height(), BlockHeight::new(0));
        });
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn test_straight_chain() {
        common::concurrency::model(|| {
            // In this test, processing a few correct blocks in a single chain
            let config = create_mainnet();
            let storage = Store::new_empty().unwrap();
            let mut consensus = Consensus::new(config.clone(), storage);

            // process the genesis block
            let block_source = BlockSource::Local;
            let mut block_index = consensus
                .process_block(config.genesis_block().clone(), block_source)
                .ok()
                .flatten()
                .expect("Unable to process genesis block");
            assert_eq!(
                consensus
                    .blockchain_storage
                    .get_best_block_id()
                    .expect(ERR_BEST_BLOCK_NOT_FOUND),
                Some(config.genesis_block().get_id())
            );
            assert_eq!(block_index.get_block_id(), &config.genesis_block().get_id());
            assert_eq!(block_index.get_prev_block_id(), &None);
            // TODO: ensure that block at height is tested after removing the next
            assert_eq!(block_index.get_chain_trust(), 1);
            assert_eq!(block_index.get_block_height(), BlockHeight::new(0));

            let mut prev_block = config.genesis_block().clone();
            for _ in 0..255 {
                let prev_block_id = block_index.get_block_id();
                let best_block_id = consensus
                    .blockchain_storage
                    .get_best_block_id()
                    .ok()
                    .flatten()
                    .expect("Unable to get best block ID");
                assert_eq!(&best_block_id, block_index.get_block_id());
                let block_source = BlockSource::Peer(1);
                let new_block = produce_test_block(&config, &prev_block, false);
                let new_block_index =
                    dbg!(consensus.process_block(new_block.clone(), block_source))
                        .ok()
                        .flatten()
                        .expect("Unable to process block");

                // TODO: ensure that block at height is tested after removing the next
                assert_eq!(
                    new_block_index.get_prev_block_id().as_ref(),
                    Some(prev_block_id)
                );
                assert!(new_block_index.get_chain_trust() > block_index.get_chain_trust());
                assert_eq!(
                    new_block_index.get_block_height(),
                    block_index.get_block_height().next_height()
                );

                block_index = new_block_index;
                prev_block = new_block;
            }
        });
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn test_reorg_simple() {
        common::concurrency::model(|| {
            let config = create_mainnet();
            let storage = Store::new_empty().unwrap();
            let mut consensus = Consensus::new(config.clone(), storage);

            // process the genesis block
            let result =
                consensus.process_block(config.genesis_block().clone(), BlockSource::Local);
            assert!(result.is_ok());
            assert_eq!(
                consensus
                    .blockchain_storage
                    .get_best_block_id()
                    .expect(ERR_BEST_BLOCK_NOT_FOUND),
                Some(config.genesis_block().get_id())
            );

            // Process the second block
            let block = produce_test_block(&config, config.genesis_block(), false);
            let new_id = Some(block.get_id());
            assert!(consensus.process_block(block, BlockSource::Local).is_ok());
            assert_eq!(
                consensus
                    .blockchain_storage
                    .get_best_block_id()
                    .expect(ERR_BEST_BLOCK_NOT_FOUND),
                new_id
            );

            // Process the parallel block and choose the better one
            let block = produce_test_block(&config, config.genesis_block(), false);
            // let new_id = Some(block.get_id());
            assert!(consensus.process_block(block.clone(), BlockSource::Local).is_ok());
            assert_ne!(
                consensus
                    .blockchain_storage
                    .get_best_block_id()
                    .expect(ERR_BEST_BLOCK_NOT_FOUND),
                Some(config.genesis_block().get_id())
            );
            assert_eq!(
                consensus
                    .blockchain_storage
                    .get_best_block_id()
                    .expect(ERR_BEST_BLOCK_NOT_FOUND),
                new_id
            );

            // Produce another block that cause reorg
            let new_block = produce_test_block(&config, &block, false);
            let new_id = Some(new_block.get_id());
            assert!(consensus.process_block(new_block, BlockSource::Local).is_ok());
            assert_eq!(
                consensus
                    .blockchain_storage
                    .get_best_block_id()
                    .expect(ERR_BEST_BLOCK_NOT_FOUND),
                new_id
            );
        });
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn test_orphans_chains() {
        common::concurrency::model(|| {
            let config = create_mainnet();
            let storage = Store::new_empty().unwrap();
            let mut consensus = Consensus::new(config.clone(), storage);

            // Process the orphan block
            let new_block = config.genesis_block().clone();
            for _ in 0..255 {
                let new_block = produce_test_block(&config, &new_block, true);
                assert_eq!(
                    consensus.process_block(new_block.clone(), BlockSource::Local),
                    Err(BlockError::Orphan)
                );
            }
        });
    }

    // TODO: reenable this test
    // #[test]
    // #[allow(clippy::eq_op)]
    // fn test_spend_inputs_simple() {
    //     common::concurrency::model(|| {
    //         let config = create_mainnet();
    //         let storage = Store::new_empty().unwrap();
    //         let mut consensus = Consensus::new(config.clone(), storage);

    //         // process the genesis block
    //         let result =
    //             consensus.process_block(config.genesis_block().clone(), BlockSource::Local);
    //         assert!(result.is_ok());
    //         assert_eq!(
    //             consensus
    //                 .blockchain_storage
    //                 .get_best_block_id()
    //                 .expect(ERR_BEST_BLOCK_NOT_FOUND),
    //             Some(config.genesis_block().get_id())
    //         );

    //         // Create a new block
    //         let block = produce_test_block(&config, config.genesis_block(), false);

    //         // Check that all tx not in the main chain
    //         for tx in block.transactions() {
    //             assert!(
    //                 consensus
    //                     .blockchain_storage
    //                     .get_mainchain_tx_index(&tx.get_id())
    //                     .expect(ERR_STORAGE_FAIL)
    //                     == None
    //             );
    //         }

    //         // Process the second block
    //         let new_id = Some(block.get_id());
    //         assert!(consensus.process_block(block.clone(), BlockSource::Local).is_ok());
    //         assert_eq!(
    //             consensus
    //                 .blockchain_storage
    //                 .get_best_block_id()
    //                 .expect(ERR_BEST_BLOCK_NOT_FOUND),
    //             new_id
    //         );

    //         // Check that tx inputs in the main chain and not spend
    //         let mut cached_inputs = CachedInputs::new();
    //         for tx in block.transactions() {
    //             let tx_index = match cached_inputs.entry(tx.get_id()) {
    //                 Entry::Occupied(entry) => entry.into_mut(),
    //                 Entry::Vacant(entry) => entry.insert(
    //                     consensus
    //                         .blockchain_storage
    //                         .get_mainchain_tx_index(&tx.get_id())
    //                         .expect("Not found mainchain tx index")
    //                         .expect(ERR_STORAGE_FAIL),
    //                 ),
    //             };

    //             for input in tx.get_inputs() {
    //                 if tx_index
    //                     .get_spent_state(input.get_outpoint().get_output_index())
    //                     .expect("Unable to get spent state")
    //                     != OutputSpentState::Unspent
    //                 {
    //                     panic!("Tx input can't be spent");
    //                 }
    //             }
    //         }
    //     });
    // }

    fn random_witness() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut witness: Vec<u8> = (1..100).collect();
        witness.shuffle(&mut rng);
        witness
    }

    fn random_address(chain_config: &ChainConfig) -> Destination {
        let mut rng = rand::thread_rng();
        let mut address: Vec<u8> = (1..22).collect();
        address.shuffle(&mut rng);
        let receiver = Address::new(chain_config, address).expect("Failed to create address");
        Destination::Address(receiver)
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn spend_tx_in_the_same_block() {
        common::concurrency::model(|| {
            // Check is it correctly spend when the second tx pointing on the first tx
            // +--Block----------------+
            // |                       |
            // | +-------tx-1--------+ |
            // | |input = prev_block | |
            // | +-------------------+ |
            // |                       |
            // | +-------tx-2--------+ |
            // | |input = tx1        | |
            // | +-------------------+ |
            // +-----------------------+
            {
                let mut consensus = setup_consensus();
                // Create base tx
                let receiver = random_address(&consensus.chain_config);

                let prev_block_tx_id = consensus
                    .chain_config
                    .genesis_block()
                    .transactions()
                    .get(0)
                    .expect("Transaction not found")
                    .get_id();

                let input = TxInput::new(
                    OutPointSourceId::Transaction(prev_block_tx_id),
                    0,
                    random_witness(),
                );
                let output = TxOutput::new(Amount::from_atoms(12345678912345), receiver.clone());

                let first_tx =
                    Transaction::new(0, vec![input], vec![output], 0).expect(ERR_CREATE_TX_FAIL);
                let first_tx_id = first_tx.get_id();

                let input = TxInput::new(first_tx_id.into(), 0, vec![]);
                let output = TxOutput::new(Amount::from_atoms(987654321), receiver);
                let second_tx =
                    Transaction::new(0, vec![input], vec![output], 0).expect(ERR_CREATE_TX_FAIL);
                // Create tx that pointing to the previous tx
                let block = Block::new(
                    vec![first_tx, second_tx],
                    Some(Id::new(
                        &consensus.chain_config.genesis_block().get_id().get(),
                    )),
                    time::get() as u32,
                    ConsensusData::None,
                )
                .expect(ERR_CREATE_BLOCK_FAIL);
                let block_id = block.get_id();

                assert!(consensus.process_block(block, BlockSource::Local).is_ok());
                assert_eq!(
                    consensus
                        .blockchain_storage
                        .get_best_block_id()
                        .expect(ERR_BEST_BLOCK_NOT_FOUND),
                    Some(block_id)
                );
            }
            // The case is invalid. Transsactions should be in order
            // +--Block----------------+
            // |                       |
            // | +-------tx-1--------+ |
            // | |input = tx2        | |
            // | +-------------------+ |
            // |                       |
            // | +-------tx-2--------+ |
            // | |input = prev_block | |
            // | +-------------------+ |
            // +-----------------------+
            {
                let mut consensus = setup_consensus();
                // Create base tx
                let receiver = random_address(&consensus.chain_config);

                let prev_block_tx_id =
                    consensus.chain_config.genesis_block().transactions().get(0).unwrap().get_id();

                let input = TxInput::new(
                    OutPointSourceId::Transaction(prev_block_tx_id),
                    0,
                    random_witness(),
                );
                let output = TxOutput::new(Amount::from_atoms(12345678912345), receiver.clone());

                let first_tx =
                    Transaction::new(0, vec![input], vec![output], 0).expect(ERR_CREATE_TX_FAIL);
                let first_tx_id = first_tx.get_id();

                let input = TxInput::new(first_tx_id.into(), 0, vec![]);
                let output = TxOutput::new(Amount::from_atoms(987654321), receiver);
                let second_tx =
                    Transaction::new(0, vec![input], vec![output], 0).expect(ERR_CREATE_TX_FAIL);
                // Create tx that pointing to the previous tx
                let block = Block::new(
                    vec![second_tx, first_tx],
                    Some(Id::new(
                        &consensus.chain_config.genesis_block().get_id().get(),
                    )),
                    time::get() as u32,
                    ConsensusData::None,
                )
                .expect(ERR_CREATE_BLOCK_FAIL);

                assert!(consensus.process_block(block, BlockSource::Local).is_err());
                assert_eq!(
                    consensus
                        .blockchain_storage
                        .get_best_block_id()
                        .expect(ERR_BEST_BLOCK_NOT_FOUND)
                        .expect(ERR_STORAGE_FAIL),
                    consensus.chain_config.genesis_block().get_id()
                );
            }
        });
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn double_spend_tx_in_the_same_block() {
        common::concurrency::model(|| {
            // Check is it correctly spend when a couple of transactions pointing on one output
            // +--Block----------------+
            // |                       |
            // | +-------tx-1--------+ |
            // | |input = prev_block | |
            // | +-------------------+ |
            // |                       |
            // | +-------tx-2--------+ |
            // | |input = tx1        | |
            // | +-------------------+ |
            // |                       |
            // | +-------tx-3--------+ |
            // | |input = tx1        | |
            // | +-------------------+ |
            // +-----------------------+

            let mut consensus = setup_consensus();
            let receiver = random_address(&consensus.chain_config);

            let prev_block_tx_id =
                consensus.chain_config.genesis_block().transactions().get(0).unwrap().get_id();

            // Create first tx
            let first_tx = Transaction::new(
                0,
                vec![TxInput::new(
                    OutPointSourceId::Transaction(prev_block_tx_id),
                    0,
                    random_witness(),
                )],
                vec![TxOutput::new(Amount::from_atoms(12345678912345), receiver.clone())],
                0,
            )
            .expect(ERR_CREATE_TX_FAIL);
            let first_tx_id = first_tx.get_id();

            // Create second tx
            let second_tx = Transaction::new(
                0,
                vec![TxInput::new(first_tx_id.clone().into(), 0, vec![])],
                vec![TxOutput::new(Amount::from_atoms(987654321), receiver.clone())],
                0,
            )
            .expect(ERR_CREATE_TX_FAIL);

            // Create third tx
            let third_tx = Transaction::new(
                123456789,
                vec![TxInput::new(first_tx_id.into(), 0, vec![])],
                vec![TxOutput::new(Amount::from_atoms(987654321), receiver)],
                0,
            )
            .expect(ERR_CREATE_TX_FAIL);

            // Create tx that pointing to the previous tx
            let block = Block::new(
                vec![first_tx, second_tx, third_tx],
                Some(Id::new(
                    &consensus.chain_config.genesis_block().get_id().get(),
                )),
                time::get() as u32,
                ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);
            assert!(consensus.process_block(block, BlockSource::Local).is_err());
            assert_eq!(
                consensus
                    .blockchain_storage
                    .get_best_block_id()
                    .expect(ERR_BEST_BLOCK_NOT_FOUND)
                    .expect(ERR_STORAGE_FAIL),
                consensus.chain_config.genesis_block().get_id()
            );
        });
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn double_spend_tx_in_another_block() {
        common::concurrency::model(|| {
            // Check is it correctly spend when a couple of transactions in a different blocks pointing on one output
            //
            // Genesis -> b1 -> b2 where
            //
            // +--Block-1--------------+
            // |                       |
            // | +-------tx-1--------+ |
            // | |input = genesis    | |
            // | +-------------------+ |
            // +-----------------------+
            //
            // +--Block-2--------------+
            // |                       |
            // | +-------tx-1--------+ |
            // | |input = genesis    | |
            // | +-------------------+ |
            // +-----------------------+

            let mut consensus = setup_consensus();
            let receiver = random_address(&consensus.chain_config);

            let prev_block_tx_id =
                consensus.chain_config.genesis_block().transactions().get(0).unwrap().get_id();

            // Create first tx
            let first_tx = Transaction::new(
                0,
                vec![TxInput::new(
                    OutPointSourceId::Transaction(prev_block_tx_id.clone()),
                    0,
                    random_witness(),
                )],
                vec![TxOutput::new(Amount::from_atoms(12345678912345), receiver.clone())],
                0,
            )
            .expect(ERR_CREATE_TX_FAIL);

            // Create tx that pointing to the previous tx
            let first_block = Block::new(
                vec![first_tx],
                Some(Id::new(
                    &consensus.chain_config.genesis_block().get_id().get(),
                )),
                time::get() as u32,
                ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);
            let first_block_id = first_block.get_id();
            assert!(consensus.process_block(first_block, BlockSource::Local).is_ok());
            assert_eq!(
                consensus
                    .blockchain_storage
                    .get_best_block_id()
                    .expect(ERR_BEST_BLOCK_NOT_FOUND),
                Some(first_block_id.clone())
            );
            // Create second tx
            let second_tx = Transaction::new(
                12345,
                vec![TxInput::new(
                    OutPointSourceId::Transaction(prev_block_tx_id),
                    0,
                    random_witness(),
                )],
                vec![TxOutput::new(Amount::from_atoms(12345678912345), receiver)],
                0,
            )
            .expect(ERR_CREATE_TX_FAIL);

            // Create tx that pointing to the previous tx
            let second_block = Block::new(
                vec![second_tx],
                Some(first_block_id.clone()),
                time::get() as u32,
                ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL);
            assert!(consensus.process_block(second_block, BlockSource::Local).is_err());
            assert_eq!(
                consensus
                    .blockchain_storage
                    .get_best_block_id()
                    .expect(ERR_BEST_BLOCK_NOT_FOUND)
                    .expect(ERR_STORAGE_FAIL),
                first_block_id
            );
        });
    }

    struct BlockTestFrameWork {
        consensus: Consensus,
        blocks: Vec<Block>,
    }

    impl<'a> BlockTestFrameWork {
        pub fn new() -> Self {
            let consensus = setup_consensus();
            let genesis = consensus.chain_config.genesis_block().clone();
            Self {
                consensus,
                blocks: vec![genesis],
            }
        }

        #[allow(dead_code)]
        pub fn random_tx(
            _parent_block: &Block,
            _params: Option<&[TxParams]>,
        ) -> Option<Transaction> {
            // match params {
            //     Some(params) => {
            //         let mut output_count = 1;
            //         let mut input_count = 1;
            //         let mut tx_fee = Amount::from_atoms(1);
            //         let mut double_spend = false;
            //         for param in params {
            //             match TxParams {
            //                 TxParams::NoErrors => continue,
            //                 TxParams::NoInputs => input_count = 0 ,
            //                 TxParams::NoOutputs => output_count = 0,
            //                 TxParams::Fee(new_fee) => tx_fee = new_fee,
            //                 TxParams::OutputsCount(count) => output_count = count,
            //                 TxParams::InputsCount(count) => input_count = count ,
            //                 TxParams::DoubleSpend => double_spend = true,
            //                 TxParams::OrphanInputs => orpan_inputs = true,
            //             }
            //         }

            //     },
            //     None => return self::random_tx(&parent_block, Some([TxParams::NoErrors])),
            // }

            // None
            unimplemented!()
        }

        #[allow(dead_code)]
        pub fn random_block(&self, parent_block: &Block, params: Option<&[BlockParams]>) -> Block {
            let (mut inputs, outputs): (Vec<TxInput>, Vec<TxOutput>) = parent_block
                .transactions()
                .iter()
                .flat_map(|tx| create_new_outputs(&self.consensus.chain_config, tx))
                .unzip();

            let mut hash_prev_block = Some(parent_block.get_id());
            if let Some(params) = params {
                for param in params {
                    match param {
                        BlockParams::DoubleSpendFrom(block_id) => {
                            let block = self
                                .consensus
                                .blockchain_storage
                                .get_block(block_id.clone())
                                .unwrap()
                                .unwrap();

                            let double_spend_input = TxInput::new(
                                OutPointSourceId::Transaction(block.transactions()[0].get_id()),
                                0,
                                vec![],
                            );
                            inputs.push(double_spend_input)
                        }
                        BlockParams::Fee(_fee_amount) => {
                            unimplemented!()
                        }
                        BlockParams::NoErrors => {
                            unimplemented!()
                        }
                        BlockParams::Orphan => hash_prev_block = Some(Id::new(&H256::random())),
                        BlockParams::TxCount(_tx_count) => {
                            unimplemented!()
                        }
                    }
                }
            }

            Block::new(
                vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
                hash_prev_block,
                time::get() as u32,
                ConsensusData::None,
            )
            .expect(ERR_CREATE_BLOCK_FAIL)
        }

        pub fn genesis(&self) -> &Block {
            self.consensus.chain_config.genesis_block()
        }

        fn get_children(current_block_id: &Id<Block>, blocks: &Vec<Block>) -> Vec<Id<Block>> {
            let mut result = Vec::new();
            for block in blocks {
                if let Some(ref prev_block_id) = block.prev_block_id() {
                    if prev_block_id == current_block_id {
                        result.push(block.get_id());
                    }
                }
            }
            result
        }

        fn get_block_index(&self, block_id: &Id<Block>) -> BlockIndex {
            self.consensus.blockchain_storage.get_block_index(block_id).unwrap().unwrap()
        }

        pub fn debug_print_chains(&self, blocks: Vec<Id<Block>>, depth: usize) {
            if blocks.is_empty() {
                println!("{}X", "--".repeat(depth));
            } else {
                for block_id in blocks {
                    let block_index = self.get_block_index(&block_id);
                    let mut main_chain = "";
                    if self.is_block_in_main_chain(&block_id) {
                        main_chain = ", M";
                    }
                    println!(
                        "{}+{} {} (H:{}{})",
                        "\t".repeat(depth),
                        "-".repeat(2),
                        &block_id.get(),
                        block_index.get_block_height(),
                        main_chain
                    );
                    let block_children = Self::get_children(&block_id, &self.blocks);
                    if !block_children.is_empty() {
                        self.debug_print_chains(block_children, depth + 1);
                    }
                }
            }
        }

        pub fn debug_print_tx(&self, block_id: Id<Block>, transactions: &Vec<Transaction>) {
            println!();
            for tx in transactions {
                println!("+ BLOCK: {} => TX: {}", block_id.get(), tx.get_id().get());
                for (output_index, output) in tx.get_outputs().iter().enumerate() {
                    let spent_status = self.get_spent_status(&tx.get_id(), output_index as u32);
                    println!("\t+Output: {}", output_index);
                    println!("\t\t+Value: {}", output.get_value().into_atoms());
                    match spent_status {
                        Some(OutputSpentState::Unspent) => println!("\t\t+Spend: Unspent"),
                        Some(OutputSpentState::SpentBy(spender)) => {
                            println!("\t\t+Spend: {:?}", spender)
                        }
                        None => println!("\t\t+Spend: Not in mainchain"),
                    }
                }
            }
        }

        pub fn create_chain(
            &mut self,
            parent_block_id: &Id<Block>,
            count_blocks: usize,
            _params: Option<ChainParams>,
        ) {
            let mut block = self
                .consensus
                .blockchain_storage
                .get_block(parent_block_id.clone())
                .ok()
                .flatten()
                .unwrap();

            for _ in 0..count_blocks {
                block = produce_test_block(&self.consensus.chain_config.clone(), &block, false);
                self.consensus
                    .process_block(block.clone(), BlockSource::Local)
                    .expect("Err block processing");
                self.blocks.push(block.clone());
            }
        }

        pub fn add_special_block(&mut self, block: Block) {
            self.consensus
                .process_block(block.clone(), BlockSource::Local)
                .expect("Err block processing");
            self.blocks.push(block);
        }

        pub fn add_blocks(&mut self, parent_block_id: &Id<Block>, count_blocks: usize) {
            let mut block = self
                .consensus
                .blockchain_storage
                .get_block(parent_block_id.clone())
                .ok()
                .flatten()
                .unwrap();
            for _ in 0..count_blocks {
                block = produce_test_block(&self.consensus.chain_config.clone(), &block, false);
                self.consensus
                    .process_block(block.clone(), BlockSource::Local)
                    .expect("Err block processing");
                self.blocks.push(block.clone());
            }
        }

        pub fn get_spent_status(
            &self,
            tx_id: &Id<Transaction>,
            output_index: u32,
        ) -> Option<OutputSpentState> {
            let tx_index =
                self.consensus.blockchain_storage.get_mainchain_tx_index(tx_id).unwrap()?;
            tx_index.get_spent_state(output_index).ok()
        }

        pub fn test_block(
            &self,
            block_id: &Id<Block>,
            prev_block_id: &Option<Id<Block>>,
            next_block_id: &Option<Id<Block>>,
            height: u64,
            spend_status: TestSpentStatus,
        ) {
            if spend_status != TestSpentStatus::NotInMainchain {
                let block = self.blocks.iter().find(|x| &x.get_id() == block_id);

                match block {
                    Some(block) => {
                        for tx in block.transactions() {
                            for (output_index, _) in tx.get_outputs().iter().enumerate() {
                                assert!(if spend_status == TestSpentStatus::Spent {
                                    self.get_spent_status(&tx.get_id(), output_index as u32)
                                        != Some(OutputSpentState::Unspent)
                                } else {
                                    self.get_spent_status(&tx.get_id(), output_index as u32)
                                        == Some(OutputSpentState::Unspent)
                                });
                            }
                        }
                    }
                    None => {
                        panic!("block not found")
                    }
                }
            }

            let block_index = self.get_block_index(block_id);
            assert_eq!(block_index.get_prev_block_id(), prev_block_id);
            assert_eq!(block_index.get_next_block_id(), next_block_id);
            assert_eq!(block_index.get_block_height(), BlockHeight::new(height));
        }

        pub fn is_block_in_main_chain(&self, block_id: &Id<Block>) -> bool {
            let block_index = self.get_block_index(block_id);
            let mut main_chain = false;
            if let Some(prev_block_id) = block_index.get_prev_block_id() {
                if self.get_block_index(prev_block_id).get_next_block_id()
                    == &Some(block_id.clone())
                {
                    main_chain = true;
                }
            }
            main_chain
        }
    }

    #[derive(Debug)]
    #[allow(dead_code)]
    pub enum ChainParams {
        NoErrors,
    }

    #[derive(Debug)]
    #[allow(dead_code)]
    pub enum TxParams {
        NoErrors,
        NoInputs,
        NoOutputs,
        Fee(Amount),
        OutputsCount(usize),
        InputsCount(usize),
        DoubleSpend,
        OrphanInputs,
    }

    #[derive(Debug)]
    #[allow(dead_code)]
    pub enum BlockParams {
        NoErrors,
        TxCount(usize),
        Fee(Amount),
        Orphan,
        DoubleSpendFrom(Id<Block>),
    }

    #[derive(Debug, Eq, PartialEq)]
    #[allow(dead_code)]
    enum TestSpentStatus {
        Spent,
        Unspent,
        NotInMainchain,
    }

    #[test]
    fn test_very_long_reorgs() {
        common::concurrency::model(|| {
            let mut btf = BlockTestFrameWork::new();
            println!("genesis id: {:?}", btf.genesis().get_id());
            // # Fork like this:
            // #
            // #     genesis -> b1 (1) -> b2 (2)
            // #                      \-> b3 (2)
            // #
            // # Nothing should happen at this point. We saw b2 first so it takes priority.
            println!("\nDon't reorg to a chain of the same length");
            btf.create_chain(&btf.genesis().get_id(), 2, None);
            btf.create_chain(&btf.blocks[1].get_id(), 1, None);
            btf.debug_print_chains(vec![btf.genesis().get_id()], 0);

            // genesis
            btf.test_block(
                &btf.blocks[0].get_id(),
                &None,
                &Some(btf.blocks[1].get_id()),
                0,
                TestSpentStatus::Spent,
            );
            // b1
            btf.test_block(
                &btf.blocks[1].get_id(),
                &Some(btf.genesis().get_id()),
                &Some(btf.blocks[2].get_id()),
                1,
                TestSpentStatus::Spent,
            );
            assert!(btf.is_block_in_main_chain(&btf.blocks[1].get_id()));
            // b2
            btf.test_block(
                &btf.blocks[2].get_id(),
                &Some(btf.blocks[1].get_id()),
                &None,
                2,
                TestSpentStatus::Unspent,
            );
            assert!(btf.is_block_in_main_chain(&btf.blocks[2].get_id()));
            // b3
            btf.test_block(
                &btf.blocks[3].get_id(),
                &Some(btf.blocks[1].get_id()),
                &None,
                2,
                TestSpentStatus::NotInMainchain,
            );
            assert!(!btf.is_block_in_main_chain(&btf.blocks[3].get_id()));
            btf.debug_print_tx(btf.blocks[3].get_id(), btf.blocks[3].transactions());

            // # Now we add another block to make the alternative chain longer.
            // #
            // #     genesis -> b1 (1) -> b2 (2)
            // #                      \-> b3 (2) -> b4 (3)
            println!("\nReorg to a longer chain");
            let block = match btf.blocks.last() {
                Some(last_block) => btf.random_block(last_block, None),
                None => panic!("Can't find block"),
            };
            btf.add_special_block(block);
            btf.debug_print_chains(vec![btf.genesis().get_id()], 0);

            // b3
            btf.test_block(
                &btf.blocks[3].get_id(),
                &Some(btf.blocks[1].get_id()),
                &Some(btf.blocks[4].get_id()),
                2,
                TestSpentStatus::Spent,
            );
            assert!(btf.is_block_in_main_chain(&btf.blocks[3].get_id()));

            // b4
            btf.test_block(
                &btf.blocks[4].get_id(),
                &Some(btf.blocks[3].get_id()),
                &None,
                3,
                TestSpentStatus::Unspent,
            );
            assert!(btf.is_block_in_main_chain(&btf.blocks[4].get_id()));

            // # ... and back to the first chain.
            // #     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6 (3)
            // #                      \-> b3 (1) -> b4 (2)
            let block_id = btf.blocks[btf.blocks.len() - 3].get_id();
            btf.add_blocks(&block_id, 2);
            btf.debug_print_chains(vec![btf.genesis().get_id()], 0);

            // b3
            btf.test_block(
                &btf.blocks[3].get_id(),
                &Some(btf.blocks[1].get_id()),
                &None,
                2,
                TestSpentStatus::NotInMainchain,
            );
            assert!(!btf.is_block_in_main_chain(&btf.blocks[3].get_id()));
            // b4
            btf.test_block(
                &btf.blocks[4].get_id(),
                &Some(btf.blocks[3].get_id()),
                &None,
                3,
                TestSpentStatus::NotInMainchain,
            );
            assert!(!btf.is_block_in_main_chain(&btf.blocks[4].get_id()));

            // b5
            btf.test_block(
                &btf.blocks[5].get_id(),
                &Some(btf.blocks[2].get_id()),
                &Some(btf.blocks[6].get_id()),
                3,
                TestSpentStatus::Spent,
            );
            assert!(btf.is_block_in_main_chain(&btf.blocks[5].get_id()));
            // b6
            btf.test_block(
                &btf.blocks[6].get_id(),
                &Some(btf.blocks[5].get_id()),
                &None,
                4,
                TestSpentStatus::Unspent,
            );
            assert!(btf.is_block_in_main_chain(&btf.blocks[6].get_id()));

            // # Try to create a fork that double-spends
            // #     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6 (3)
            // #                                          \-> b7 (2) -> b8 (4)
            // #                      \-> b3 (1) -> b4 (2)
            println!("\nReject a chain with a double spend, even if it is longer");
            //TODO: Should be fail
            let block_id = btf.blocks[btf.blocks.len() - 5].get_id();
            btf.create_chain(&block_id, 2, None);
            let block_id = btf.blocks[btf.blocks.len() - 7].get_id();
            //TODO: Not finished yet
            let double_spend_block = btf.random_block(
                btf.blocks.last().unwrap(),
                Some(&[BlockParams::DoubleSpendFrom(block_id)]),
            );
            // btf.add_special_block(double_spend_block);
            btf.debug_print_chains(vec![btf.genesis().get_id()], 0);

            //     // // # Try to create a block that has too much fee
            //     // // #     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6 (3)
            //     // // #                                                    \-> b9 (4)
            //     // // #                      \-> b3 (1) -> b4 (2)

            //     println!("\nReject a block where the miner creates too much reward");
            //     //TODO: Not finished yet
            //     let exceed_fee_block = btf.random_block(
            //         btf.blocks.last().unwrap(),
            //         Some(&[BlockParams::Fee(Amount::from_atoms(u128::MAX))]),
            //     );
            //     btf.add_special_block(exceed_fee_block);
            //     btf.debug_print_chains(vec![btf.genesis().get_id()], 0);

            //     // // # Create a fork that ends in a block with too much fee (the one that causes the reorg)
            //     // // #     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
            //     // // #                                          \-> b10 (3) -> b11 (4)
            //     // // #                      \-> b3 (1) -> b4 (2)
            //     let exceed_fee_block = btf.random_block(
            //         btf.blocks.last().unwrap(),
            //         Some(&[BlockParams::Fee(Amount::from_atoms(u128::MAX))]),
            //     );
            //     btf.add_special_block(exceed_fee_block);
            //     btf.debug_print_chains(vec![btf.genesis().get_id()], 0);
            //     // # Try again, but with a valid fork first
            //     // #     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
            //     // #                                          \-> b12 (3) -> b13 (4) -> b14 (5)
            //     // #                      \-> b3 (1) -> b4 (2)
            //     let exceed_fee_block = btf.random_block(
            //         btf.blocks.last().unwrap(),
            //         Some(&[BlockParams::Fee(Amount::from_atoms(u128::MAX))]),
            //     );
            //     btf.add_special_block(exceed_fee_block);
            //     btf.debug_print_chains(vec![btf.genesis().get_id()], 0);

            //     // # Attempt to spend a transaction created on a different fork
            //     // #     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
            //     // #                                          \-> b12 (3) -> b13 (4) -> b15 (5) -> b17 (b3.vtx[1])
            //     // #                      \-> b3 (1) -> b4 (2)
        });
    }

    // TODO: Not ready tests for this PR:
    // * Empty block checks
    // * Check chains with skips and forks
    // * Check blocks at heights
    // * Fail cases for block processing
    // * Tests multichains reorgs
    // * Tests different sorts of attacks - double spend \ Sybil \ etc
    // To be expanded
}
