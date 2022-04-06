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
use common::chain::config::ChainConfig;
use common::chain::{
    OutPoint, OutPointSourceId, OutputSpentState, SpendablePosition, Spender, Transaction,
    TxMainChainIndex, TxMainChainPosition,
};
use common::chain::{SpendError, TxMainChainIndexError};
use common::primitives::{time, Amount, BlockHeight, Id, Idable};
use std::collections::btree_map::Entry;
use thiserror::Error;
mod orphan_blocks;
use parity_scale_codec::Encode;
use std::collections::BTreeMap;

type CachedInputs = BTreeMap<Id<Transaction>, TxMainChainIndex>;
type PeerId = u32;
type TxRw<'a> = <blockchain_storage::Store as Transactional<'a>>::TransactionRw;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum BlockError {
    #[error("Unknown error")]
    Unknown,
    // Orphan block
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
    fn from(_: SpendError) -> Self {
        // To be expanded
        BlockError::Unknown
    }
}

impl From<TxMainChainIndexError> for BlockError {
    fn from(_: TxMainChainIndexError) -> Self {
        // To be expanded
        BlockError::Unknown
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
    fn get_previous_block_index(&self, block_id: &Id<Block>) -> Result<BlockIndex, BlockError> {
        let block_index = self
            .db_tx
            .get_block_index(block_id)
            .map_err(BlockError::from)?
            .ok_or(BlockError::NotFound)?;
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
        while !self.is_block_in_main_chain(&block_index) {
            result.push(block_index.clone());
            block_index = self.get_previous_block_index(block_index.get_block_id())?;
        }
        result.reverse();
        Ok(result)
    }

    fn reorganize(
        &mut self,
        best_block_id: Option<Id<Block>>,
        new_block_index: &BlockIndex,
    ) -> Result<(), BlockError> {
        let new_chain = self.get_new_chain(new_block_index)?;

        // Disconnect the current chain if it is not a genesis
        if let Some(ref best_block_id) = best_block_id {
            let common_ancestor = self.get_previous_block_index(
                new_chain.get(0).ok_or(BlockError::Unknown)?.get_block_id(),
            )?;
            let mut current_ancestor = self
                .db_tx
                .get_block_index(best_block_id)?
                .expect("Can't get block index. Inconsistent DB");

            // Disconnect blocks
            while self.is_block_in_main_chain(&current_ancestor)
                && current_ancestor.get_block_id() != common_ancestor.get_block_id()
            {
                self.disconnect_tip(&mut current_ancestor)?;
                current_ancestor =
                    self.get_previous_block_index(current_ancestor.get_block_id())?;
            }
        }

        // Connect the new chain
        for block_index in new_chain {
            self.connect_tip(&block_index)?;
        }
        Ok(())
    }

    fn store_cached_inputs(&mut self, cached_inputs: &CachedInputs) -> Result<(), BlockError> {
        for (tx_id, tx_index) in cached_inputs {
            self.db_tx.set_mainchain_tx_index(tx_id, tx_index)?;
        }
        Ok(())
    }

    fn calculate_indices(
        &self,
        block: &Block,
        tx: &Transaction,
    ) -> Result<TxMainChainIndex, BlockError> {
        let enc_block = block.encode();
        let enc_tx = tx.encode();
        let offset_tx = enc_block
            .windows(enc_tx.len())
            .enumerate()
            .find_map(|(i, d)| (d == enc_tx).then(|| i))
            .ok_or(BlockError::Unknown)?
            .try_into()
            .map_err(|_| BlockError::Unknown)?;

        let tx_position = TxMainChainPosition::new(
            &block.get_id().get(),
            offset_tx,
            enc_tx.len().try_into().map_err(|_| BlockError::Unknown)?,
        );

        assert_eq!(
            &self
                .db_tx
                .get_mainchain_tx_by_position(&tx_position)
                .ok()
                .flatten()
                .expect("Database corrupted! "),
            tx
        );

        TxMainChainIndex::new(
            SpendablePosition::from(tx_position),
            tx.get_outputs().len().try_into().map_err(|_| BlockError::Unknown)?,
        )
        .map_err(BlockError::from)
    }

    fn connect_transactions(&mut self, block: &Block) -> Result<(), BlockError> {
        let mut cached_inputs = CachedInputs::new();
        for tx in block.transactions() {
            let tx_index = match cached_inputs.entry(tx.get_id()) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => entry.insert(self.calculate_indices(block, tx)?),
            };
            for input in tx.get_inputs() {
                let input_index = input.get_outpoint().get_output_index();

                if input_index >= tx_index.get_output_count() {
                    return Err(BlockError::Unknown);
                }
                // Set each input as spent
                tx_index
                    .spend(input_index, Spender::from(tx.get_id()))
                    .map_err(BlockError::from)?;
            }
        }
        self.store_cached_inputs(&cached_inputs)?;
        Ok(())
    }

    fn disconnect_transactions(&mut self, transactions: &[Transaction]) -> Result<(), BlockError> {
        let mut cached_inputs = CachedInputs::new();
        for tx in transactions.iter().rev() {
            let tx_index = match cached_inputs.entry(tx.get_id()) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => entry.insert(
                    self.db_tx.get_mainchain_tx_index(&tx.get_id())?.ok_or(BlockError::Unknown)?,
                ),
            };
            for input in tx.get_inputs() {
                let input_index = input.get_outpoint().get_output_index();

                if input_index >= tx_index.get_output_count() {
                    return Err(BlockError::Unknown);
                }
                tx_index.unspend(input_index).map_err(BlockError::from)?;
            }
            // TODO: Seems, would be better to remove TxMainChainIndex for disconnected block.
            // self.db_tx.del_mainchain_tx_index(&tx.get_id())?;
        }
        self.store_cached_inputs(&cached_inputs)?;
        Ok(())
    }

    fn get_mainchain_index_by_outpoint<TxRo: BlockchainStorageRead>(
        tx_db: &TxRo,
        outpoint: &OutPoint,
    ) -> Result<TxMainChainIndex, BlockError> {
        let tx_id = match outpoint.get_tx_id() {
            OutPointSourceId::Transaction(tx_id) => tx_id,
            OutPointSourceId::BlockReward(_) => {
                unimplemented!()
            }
        };
        tx_db.get_mainchain_tx_index(&tx_id)?.ok_or(BlockError::Unknown)
    }

    fn get_tx_by_outpoint<TxRo: BlockchainStorageRead>(
        tx_db: &TxRo,
        outpoint: &OutPoint,
    ) -> Result<Transaction, BlockError> {
        let tx_id = match outpoint.get_tx_id() {
            OutPointSourceId::Transaction(tx_id) => tx_id,
            OutPointSourceId::BlockReward(_) => {
                unimplemented!()
            }
        };
        let tx_index = tx_db.get_mainchain_tx_index(&tx_id)?.ok_or(BlockError::Unknown)?;
        match tx_index.get_tx_position() {
            SpendablePosition::Transaction(position) => {
                tx_db.get_mainchain_tx_by_position(position)?.ok_or(BlockError::Unknown)
            }
            SpendablePosition::BlockReward(_) => unimplemented!(),
        }
    }

    fn get_output_by_outpoint<TxRo: BlockchainStorageRead>(
        tx_db: &TxRo,
        outpoint: &OutPoint,
    ) -> Result<common::chain::TxOutput, BlockError> {
        let tx = Self::get_tx_by_outpoint(tx_db, outpoint)?;
        let output_index: usize =
            outpoint.get_output_index().try_into().map_err(|_| BlockError::Unknown)?;
        assert!(output_index < tx.get_outputs().len());
        tx.get_outputs().get(output_index).ok_or(BlockError::Unknown).cloned()
    }

    fn get_input_value<TxRo: BlockchainStorageRead>(
        tx_db: &TxRo,
        input: &common::chain::TxInput,
    ) -> Result<Amount, BlockError> {
        let tx = Self::get_tx_by_outpoint(tx_db, input.get_outpoint())?;
        let output_index: usize = input
            .get_outpoint()
            .get_output_index()
            .try_into()
            .map_err(|_| BlockError::Unknown)?;
        assert!(output_index < tx.get_outputs().len());
        tx.get_outputs()
            .get(output_index)
            .map(|output| output.get_value())
            .ok_or(BlockError::Unknown)
    }

    fn check_block_fee(&self, transactions: &[Transaction]) -> Result<(), BlockError> {
        let input_mlt = transactions
            .iter()
            .map(|x| {
                x.get_inputs()
                    .iter()
                    .map(|input| {
                        Self::get_input_value(&self.db_tx, input).expect("Couldn't get input")
                    })
                    .sum::<Amount>()
            })
            .sum();
        let output_mlt: Amount = transactions
            .iter()
            .map(|x| x.get_outputs().iter().map(|output| output.get_value()).sum::<Amount>())
            .sum();

        // Check that fee is not negative
        if output_mlt > input_mlt {
            return Err(BlockError::Unknown);
        }
        Ok(())
    }

    fn check_tx_inputs(&self, transactions: &[Transaction]) -> Result<(), BlockError> {
        let mut total_value = Amount::new(0);
        for tx in transactions {
            for input in tx.get_inputs() {
                let tx_index =
                    Self::get_mainchain_index_by_outpoint(&self.db_tx, input.get_outpoint())?;
                // If there is a wrong input index then it's cause a BlockError
                let output = Self::get_output_by_outpoint(&self.db_tx, input.get_outpoint())?;

                // Check is input has already spent
                if tx_index
                    .get_spent_state(input.get_outpoint().get_output_index())
                    .map_err(BlockError::from)?
                    == OutputSpentState::Unspent
                {
                    return Err(BlockError::Unknown);
                }
                // Check overflow
                total_value = (total_value + output.get_value()).ok_or(BlockError::Unknown)?;
            }
        }
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

    // Connect new block
    fn connect_tip(&mut self, new_tip_block_index: &BlockIndex) -> Result<(), BlockError> {
        if &self.db_tx.get_best_block_id()? != new_tip_block_index.get_prev_block_id() {
            return Err(BlockError::Unknown);
        }
        let block = self.get_block_from_index(new_tip_block_index)?.expect("Inconsistent DB");
        let transactions = block.transactions();

        if !block.is_genesis(self.chain_config) {
            self.check_block_fee(transactions)?;
            self.check_tx_inputs(transactions)?;
        }
        self.check_tx_outputs(transactions)?;
        self.connect_transactions(&block)?;

        if let Some(prev_block_id) = &new_tip_block_index.get_prev_block_id() {
            // To connect a new block we should set-up the next_block_id field of the previous block index
            let mut prev_block = self
                .db_tx
                .get_block_index(prev_block_id)?
                .expect("Can't get block index. Inconsistent DB");
            prev_block.set_next_block_id(block.get_id());
            self.db_tx
                .set_block_index(&prev_block)
                .expect("Can't set block index. Inconsistent DB");
        }
        self.db_tx.set_block_index(new_tip_block_index)?;
        self.db_tx.set_best_block_id(new_tip_block_index.get_block_id())?;
        Ok(())
    }

    fn disconnect_tip(&mut self, block_index: &mut BlockIndex) -> Result<(), BlockError> {
        assert_eq!(
            &self.db_tx.get_best_block_id().ok().flatten().expect("Only fails at genesis"),
            block_index.get_block_id()
        );
        let block = self.get_block_from_index(block_index)?.expect("Inconsistent DB");
        // Disconnect transactions
        self.disconnect_transactions(block.transactions())?;
        self.db_tx.set_best_block_id(
            block_index.get_prev_block_id().as_ref().ok_or(BlockError::Unknown)?,
        )?;
        // Disconnect block
        let mut ancestor = self.get_previous_block_index(block_index.get_block_id())?;
        ancestor.unset_next_block_id();
        self.db_tx.set_block_index(&ancestor)?;
        Ok(())
    }

    fn try_connect_genesis_block(
        &mut self,
        new_block_index: &BlockIndex,
        best_block_id: &Option<Id<Block>>,
    ) -> Result<Option<BlockIndex>, BlockError> {
        if best_block_id.is_none() && new_block_index.is_genesis(self.chain_config) {
            self.connect_tip(new_block_index)?;
            self.db_tx
                .set_best_block_id(new_block_index.get_block_id())
                .map_err(BlockError::from)?;
            return Ok(Some(new_block_index.clone()));
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
        let best_block_id = best_block_id.expect("Best block must be set");
        // Chain trust is higher than the best block
        let current_best_block_index = self
            .db_tx
            .get_block_index(&best_block_id)
            .map_err(BlockError::from)?
            .expect("Inconsistent DB");
        if new_block_index.get_chain_trust() > current_best_block_index.get_chain_trust() {
            self.reorganize(Some(best_block_id), &new_block_index)?;
            return Ok(Some(new_block_index));
        } else {
            // TODO: we don't store block indexes for blocks we don't accept, because this is PoS
            self.db_tx.set_block_index(&new_block_index)?;
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

    fn block_exists(&self, id: &Id<Block>) -> Result<bool, BlockError> {
        Ok(self.db_tx.get_block_index(id)?.is_some())
    }

    fn check_block_index(&self, block_index: &BlockIndex) -> Result<(), BlockError> {
        // BlockIndex is already known or block exists
        if self.db_tx.get_block_index(block_index.get_block_id())?.is_some()
            || self.block_exists(block_index.get_block_id())?
        {
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
        // TODO: Must check for duplicate inputs (see CVE-2018-17144)
        //      We should discuss - can we add Hash trait to Transaction?
        //      We will have plenty more checks with inputs\outputs and HashSet\BTreeMap might be more efficient
        //
        // let mut keyed = HashSet::new();
        // for tx in block.get_transactions() {
        //     for input in tx.get_inputs() {
        //         if keyed.contains(input.get_outpoint()) {
        //             return Err(BlockError::Unknown);
        //         }
        //         keyed.insert(input.get_outpoint());
        //     }
        // }

        //TODO: Size limits
        if block.encoded_size() > MAX_BLOCK_WEIGHT {
            return Err(BlockError::Unknown);
        }
        //TODO: Check signatures will be added when will ready BLS
        Ok(())
    }

    fn check_block(&self, block: &Block, block_source: BlockSource) -> Result<(), BlockError> {
        self.check_consensus(block)?;
        self.check_block_detail(block, block_source)?;
        Ok(())
    }

    fn is_block_in_main_chain(&self, block_index: &BlockIndex) -> bool {
        block_index.get_next_block_id().is_some()
            || self
                .db_tx
                .get_best_block_id()
                .ok()
                .flatten()
                .map_or(false, |ref block_id| block_index.get_block_id() == block_id)
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
    use common::chain::{Destination, Transaction, TxInput, TxOutput};
    use common::primitives::{Amount, Id};

    fn produce_test_block(config: &ChainConfig, prev_block: &Block, orphan: bool) -> Block {
        use common::primitives::H256;
        use rand::prelude::*;

        // For each output we create a new input and output that will placed into a new block.
        // If value of original output is less than 1 then output will disappear in a new block.
        // Otherwise, value will be decreasing for 1.
        let (inputs, outputs): (Vec<TxInput>, Vec<TxOutput>) = prev_block
            .transactions()
            .iter()
            .flat_map(|tx| {
                let tx_id = tx.get_id();
                tx.get_outputs()
                    .iter()
                    .enumerate()
                    .filter_map(move |(index, output)| {
                        if output.get_value() > Amount::from(1) {
                            // Random address receiver
                            let mut rng = rand::thread_rng();
                            let mut witness: Vec<u8> = (1..100).collect();
                            witness.shuffle(&mut rng);
                            let mut address: Vec<u8> = (1..22).collect();
                            address.shuffle(&mut rng);
                            let receiver =
                                Address::new(config, address).expect("Failed to create address");
                            Some((
                                TxInput::new(
                                    OutPointSourceId::Transaction(tx_id.clone()),
                                    index as u32,
                                    witness,
                                ),
                                TxOutput::new(
                                    (output.get_value() - Amount::from(1)).unwrap(),
                                    Destination::Address(receiver),
                                ),
                            ))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<(TxInput, TxOutput)>>()
            })
            .unzip();

        Block::new(
            vec![Transaction::new(0, inputs, outputs, 0).expect("Failed to create transaction")],
            if orphan {
                Some(Id::new(&H256::random()))
            } else {
                Some(Id::new(&prev_block.get_id().get()))
            },
            time::get() as u32,
            ConsensusData::None,
        )
        .expect("Error creating block")
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
                    .expect("Best block didn't found"),
                Some(config.genesis_block().get_id())
            );
            assert_eq!(block_index.get_prev_block_id(), &None);
            assert_eq!(block_index.get_next_block_id(), &None);
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
                .unwrap();
            assert_eq!(
                consensus
                    .blockchain_storage
                    .get_best_block_id()
                    .expect("Best block didn't found"),
                Some(config.genesis_block().get_id())
            );
            assert_eq!(block_index.get_block_id(), &config.genesis_block().get_id());
            assert_eq!(block_index.get_prev_block_id(), &None);
            assert_eq!(block_index.get_next_block_id(), &None);
            assert_eq!(block_index.get_chain_trust(), 1);
            assert_eq!(block_index.get_block_height(), BlockHeight::new(0));

            let mut prev_block = config.genesis_block().clone();
            for _ in 0..255 {
                let prev_block_id = block_index.get_block_id();
                let best_block_id =
                    consensus.blockchain_storage.get_best_block_id().ok().flatten().unwrap();
                assert_eq!(&best_block_id, block_index.get_block_id());
                let block_source = BlockSource::Peer(1);
                let new_block = produce_test_block(&config, &prev_block, false);
                let new_block_index = consensus
                    .process_block(new_block.clone(), block_source)
                    .ok()
                    .flatten()
                    .unwrap();

                assert_eq!(new_block_index.get_next_block_id(), &None);
                assert_eq!(
                    new_block_index.get_prev_block_id().as_ref(),
                    Some(prev_block_id)
                );
                assert!(new_block_index.get_chain_trust() > block_index.get_chain_trust());
                assert_eq!(
                    new_block_index.get_block_height(),
                    block_index.get_block_height().next_height()
                );

                let next_block_id = consensus
                    .blockchain_storage
                    .get_block_index(&new_block_index.get_prev_block_id().clone().unwrap())
                    .ok()
                    .flatten()
                    .unwrap()
                    .get_next_block_id()
                    .clone()
                    .unwrap();
                assert_eq!(&next_block_id, new_block_index.get_block_id());
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
                    .expect("Best block didn't found"),
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
                    .expect("Best block didn't found"),
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
                    .expect("Best block didn't found"),
                Some(config.genesis_block().get_id())
            );
            assert_eq!(
                consensus
                    .blockchain_storage
                    .get_best_block_id()
                    .expect("Best block didn't found"),
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
                    .expect("Best block didn't found"),
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

    #[test]
    #[allow(clippy::eq_op)]
    fn test_spend_inputs_simple() {
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
                    .expect("Best block didn't found"),
                Some(config.genesis_block().get_id())
            );

            // Create a new block
            let block = produce_test_block(&config, config.genesis_block(), false);

            // Check that all tx not in the main chain
            for tx in block.transactions() {
                assert!(
                    consensus
                        .blockchain_storage
                        .get_mainchain_tx_index(&tx.get_id())
                        .expect("DB corrupted")
                        == None
                );
            }

            // Process the second block
            let new_id = Some(block.get_id());
            assert!(consensus.process_block(block.clone(), BlockSource::Local).is_ok());
            assert_eq!(
                consensus
                    .blockchain_storage
                    .get_best_block_id()
                    .expect("Best block didn't found"),
                new_id
            );

            // Check that tx inputs in the main chain and has already spent
            let mut cached_inputs = CachedInputs::new();
            for tx in block.transactions() {
                let tx_index = match cached_inputs.entry(tx.get_id()) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => entry.insert(
                        consensus
                            .blockchain_storage
                            .get_mainchain_tx_index(&tx.get_id())
                            .expect("DB corrupted")
                            .expect("Not found mainchain tx index"),
                    ),
                };

                for input in tx.get_inputs() {
                    if tx_index.get_spent_state(input.get_outpoint().get_output_index()).unwrap()
                        == OutputSpentState::Unspent
                    {
                        panic!("Tx input can't be unspent");
                    }
                }
            }
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
