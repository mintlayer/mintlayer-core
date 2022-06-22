use crate::chain::block::Block;
use crate::chain::block::ConsensusData;
use crate::chain::transaction::Transaction;
use crate::chain::ChainConfig;
use crate::primitives::id;
use crate::primitives::id::Idable;
use crate::primitives::{Id, VersionTag, H256};

use serialization::{Decode, Encode};

use super::consensus_data::BlockRewardTransactable;
use super::timestamp::BlockTimestamp;

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Encode, Decode, serialization::Tagged)]
pub struct BlockHeader {
    pub(super) version: VersionTag<1>,
    pub(super) prev_block_id: Option<Id<Block>>,
    pub(super) tx_merkle_root: Option<H256>,
    pub(super) witness_merkle_root: Option<H256>,
    pub(super) timestamp: BlockTimestamp,
    pub(super) consensus_data: ConsensusData,
}

impl BlockHeader {
    pub fn consensus_data(&self) -> &ConsensusData {
        &self.consensus_data
    }

    pub fn block_id(&self) -> Id<Block> {
        Id::new(&id::hash_encoded(self))
    }

    pub fn is_genesis(&self, chain_config: &ChainConfig) -> bool {
        self.prev_block_id == None && chain_config.genesis_block_id() == self.block_id()
    }

    pub fn prev_block_id(&self) -> &Option<Id<Block>> {
        &self.prev_block_id
    }

    pub fn timestamp(&self) -> BlockTimestamp {
        self.timestamp
    }

    pub fn block_reward_transactable(&self) -> BlockRewardTransactable {
        self.consensus_data.derive_transactable()
    }
}

impl Idable for BlockHeader {
    type Tag = Block;
    fn get_id(&self) -> Id<Block> {
        Id::new(&id::hash_encoded(self))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, serialization::Tagged)]
pub struct BlockV1 {
    pub(super) header: BlockHeader,
    pub(super) transactions: Vec<Transaction>,
}

impl Idable for BlockV1 {
    type Tag = Block;
    fn get_id(&self) -> Id<Block> {
        Id::new(&id::hash_encoded(self.header()))
    }
}

impl BlockV1 {
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

    pub fn timestamp(&self) -> BlockTimestamp {
        self.header.timestamp()
    }

    pub fn transactions(&self) -> &Vec<Transaction> {
        &self.transactions
    }

    pub fn prev_block_id(&self) -> &Option<Id<Block>> {
        &self.header.prev_block_id
    }
}
