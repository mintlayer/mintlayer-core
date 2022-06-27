use parity_scale_codec::{Decode, Encode};

use super::consensus_data::BlockRewardTransactable;
use super::timestamp::BlockTimestamp;
use super::{Block, ConsensusData};
use crate::chain::ChainConfig;
use crate::primitives::id::{Id, Idable, H256};
use crate::primitives::{id, VersionTag};

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
