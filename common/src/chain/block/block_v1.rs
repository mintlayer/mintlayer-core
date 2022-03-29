use crate::chain::block::ConsensusData;
use crate::chain::transaction::Transaction;
use crate::primitives::{id, Id, Idable, H256};
use parity_scale_codec_derive::{Decode as DecodeDer, Encode as EncodeDer};

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, EncodeDer, DecodeDer)]
pub struct BlockHeader {
    pub(super) prev_block_hash: Option<Id<BlockV1>>,
    pub(super) tx_merkle_root: H256,
    pub(super) witness_merkle_root: H256,
    pub(super) time: u32,
    pub(super) consensus_data_inner: ConsensusData,
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, EncodeDer, DecodeDer)]
pub struct BlockV1 {
    pub(super) header: BlockHeader,
    pub(super) transactions: Vec<Transaction>,
}

impl BlockV1 {
    // This has to be the same its index in the Block enum
    pub const VERSION_BYTE: u8 = 0x01;

    pub fn tx_merkle_root(&self) -> H256 {
        self.header.tx_merkle_root
    }

    pub fn witness_merkle_root(&self) -> H256 {
        self.header.witness_merkle_root
    }

    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    pub fn update_consensus_data(&mut self, consensus_data: ConsensusData) {
        self.header.consensus_data_inner = consensus_data;
    }

    pub fn consensus_data(&self) -> &ConsensusData {
        &self.header.consensus_data_inner
    }

    pub fn block_time(&self) -> u32 {
        self.header.time
    }

    pub fn transactions(&self) -> &Vec<Transaction> {
        &self.transactions
    }

    pub fn get_prev_block_id(&self) -> &Option<Id<BlockV1>> {
        &self.header.prev_block_hash
    }
}

impl Idable<BlockV1> for BlockV1 {
    fn get_id(&self) -> Id<Self> {
        // Block ID is just the hash of its header. The transaction list is committed to by the
        // inclusion of transaction Merkle root in the header. We also include the version number.
        Id::new(&id::hash_encoded(&(Self::VERSION_BYTE, self.header())))
    }
}
