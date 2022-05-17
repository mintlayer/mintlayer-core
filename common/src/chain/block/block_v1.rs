use crate::chain::block::Block;
use crate::chain::block::ConsensusData;
use crate::chain::transaction::Transaction;
use crate::primitives::{Id, H256};

use serialization::{Decode, Encode};

use super::BlockVersion;

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Encode, Decode)]
pub struct BlockHeader {
    #[codec(compact)]
    pub(super) block_version: u32,
    pub(super) prev_block_hash: Option<Id<Block>>,
    pub(super) tx_merkle_root: Option<H256>,
    pub(super) witness_merkle_root: Option<H256>,
    #[codec(compact)]
    pub(super) time: u32,
    pub(super) consensus_data: ConsensusData,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BlockV1 {
    pub(super) header: BlockHeader,
    pub(super) transactions: Vec<Transaction>,
}

impl BlockVersion for BlockV1 {
    const BLOCK_VERSION: u32 = 1;
}

impl BlockV1 {
    pub fn check_version(&self) -> Result<(), super::BlockConsistencyError> {
        let a = self.header.block_version;
        let b = <Self as BlockVersion>::static_version(&self);
        if a != b {
            return Err(super::BlockConsistencyError::VersionMismatch(a, b));
        }
        Ok(())
    }

    pub fn version(&self) -> u32 {
        self.header.block_version
    }

    pub fn tx_merkle_root(&self) -> Option<H256> {
        self.header.tx_merkle_root
    }

    pub fn witness_merkle_root(&self) -> Option<H256> {
        self.header.witness_merkle_root
    }

    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    pub fn update_consensus_data(&mut self, consensus_data: ConsensusData) {
        self.header.consensus_data = consensus_data;
    }

    pub fn consensus_data(&self) -> &ConsensusData {
        &self.header.consensus_data
    }

    pub fn block_time(&self) -> u32 {
        self.header.time
    }

    pub fn transactions(&self) -> &Vec<Transaction> {
        &self.transactions
    }

    pub fn get_prev_block_id(&self) -> &Option<Id<Block>> {
        &self.header.prev_block_hash
    }
}
