use crate::chain::block::block_v1::BlockHeader;
use crate::chain::block::Block;
use crate::chain::ChainConfig;
use crate::primitives::{BlockHeight, Id, Idable};
// use crate::Uint256;
use parity_scale_codec::{Decode, Encode};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BlockIndexError {
    #[error("Block not found")]
    BlockNotFound,
    #[error("BlockIndex not found")]
    BlockIndexNotFound,
    #[error("DB read error")]
    DatabaseReadError,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[allow(dead_code, unused_variables)]
pub struct BlockIndex {
    block_id: Id<Block>,
    block_header: BlockHeader,
    // TODO: When Carla finish her code, we should use Uint256 at the moment it's unable to store to DB
    //  pub chain_trust: Uint256,
    chain_trust: u128,
    height: BlockHeight,
    // TODO: Make a type for block time. ISSUE: https://github.com/mintlayer/mintlayer-core/issues/127
    // TODO: Discuss with Sam
    time_max: u32,
}

impl BlockIndex {
    pub fn new(block: &Block, chain_trust: u128, height: BlockHeight, time_max: u32) -> Self {
        // We have to use the whole block because we are not able to take block_hash from the header
        Self {
            block_header: block.header().to_owned(),
            block_id: block.get_id(),
            chain_trust,
            height,
            time_max,
        }
    }

    pub fn get_block_id(&self) -> &Id<Block> {
        &self.block_id
    }

    pub fn get_prev_block_id(&self) -> &Option<Id<Block>> {
        &self.block_header.prev_block_hash
    }

    pub fn is_genesis(&self, chain_config: &ChainConfig) -> bool {
        self.block_header.prev_block_hash == None
            && chain_config.genesis_block().get_id() == self.block_id
    }

    // TODO: Make a type for block time. ISSUE: https://github.com/mintlayer/mintlayer-core/issues/127
    pub fn get_block_time(&self) -> u32 {
        self.block_header.time
    }

    // TODO: Make a type for block time. ISSUE: https://github.com/mintlayer/mintlayer-core/issues/127
    pub fn get_block_time_max(&self) -> u32 {
        self.time_max
    }

    pub fn get_block_height(&self) -> BlockHeight {
        self.height
    }

    pub fn get_chain_trust(&self) -> u128 {
        self.chain_trust
    }

    pub fn get_block_header(&self) -> &BlockHeader {
        &self.block_header
    }
}

#[cfg(test)]
mod tests {
    /*
    use super::*;
    use crate::chain::block::Block;
    use crate::chain::block::ConsensusData;
    use blockchain_storage::BlockchainStorageRead;
    use blockchain_storage::Transactional;

    struct TestBlockIndexDBAccessor {
        blockchain_storage: blockchain_storage::Store,
    }

    impl BlockIndexDBAccessor for TestBlockIndexDBAccessor {
        fn get_previous_block_index(
            &self,
            block_index: &BlockIndex,
        ) -> Result<Option<BlockIndex>, BlockIndexError> {
            let prev_block_id = block_index
                .get_prev_block_id()
                .as_ref()
                .ok_or(BlockIndexError::BlockIndexNotFound)?;
            let db_tx = self.blockchain_storage.transaction_ro();
            db_tx.get_block_index(prev_block_id)?.ok_or(BlockIndex::BlockNotFound)
        }
    }
    */

    /*
    #[test]
    fn test_get_ancestor() {
        let transactions = Vec::default();
        let hash_prev_block = None;
        let time = 0;
        let consensus_data = ConsensusData::None;
        let chain_trust = 0;
        let time_max = 0;

        let block0 = Block::new(
            transactions.clone(),
            hash_prev_block.clone(),
            time,
            consensus_data.clone(),
        )
        .expect("block0");

        let _block1 = Block::new(
            transactions.clone(),
            hash_prev_block.clone(),
            time,
            consensus_data.clone(),
        )
        .expect("block1");

        let _block2 = Block::new(
            transactions.clone(),
            hash_prev_block.clone(),
            time,
            consensus_data.clone(),
        )
        .expect("block2");

        let _block3 =
            Block::new(transactions, hash_prev_block, time, consensus_data).expect("block1");

        let height_block0 = 0;
        let _block0_index = BlockIndex::new(
            &block0,
            chain_trust,
            BlockHeight::from(height_block0),
            time_max,
        );
    }
    */
}
