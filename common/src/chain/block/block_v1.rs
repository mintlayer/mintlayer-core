use crate::chain::transaction::Transaction;
use crate::primitives::{id, Id, Idable, H256};
use parity_scale_codec_derive::{Decode as DecodeDer, Encode as EncodeDer};

#[derive(Debug, Clone, PartialEq, Eq, EncodeDer, DecodeDer)]
pub struct BlockHeader {
    pub(super) hash_prev_block: Id<BlockV1>,
    pub(super) tx_merkle_root: H256,
    pub(super) witness_merkle_root: H256,
    pub(super) time: u32,
    pub(super) consensus_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, EncodeDer, DecodeDer)]
pub struct BlockV1 {
    pub(super) header: BlockHeader,
    pub(super) transactions: Vec<Transaction>,
}

impl BlockV1 {
    pub fn get_tx_merkle_root(&self) -> H256 {
        self.header.tx_merkle_root
    }

    pub fn get_witness_merkle_root(&self) -> H256 {
        self.header.witness_merkle_root
    }

    pub fn get_header(&self) -> &BlockHeader {
        &self.header
    }

    pub fn get_consensus_data(&self) -> &ConsensusData {
        &self.get_header().consensus_data
    }
    pub fn update_consensus_data(&mut self, consensus_data: ConsensusData) {
        self.header.consensus_data = consensus_data;
    }

    pub fn get_block_time(&self) -> u32 {
        self.header.time
    }

    pub fn get_transactions(&self) -> &Vec<Transaction> {
        &self.transactions
    }

    pub fn get_prev_block_id(&self) -> &Id<BlockV1> {
        &self.header.hash_prev_block
    }
}

impl Idable<BlockV1> for BlockV1 {
    fn get_id(&self) -> Id<Self> {
        Id::new(&id::hash_encoded(self))
    }
}
