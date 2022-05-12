use common::chain::block::Block;
use common::chain::block::BlockIndex;
use common::chain::block::ConsensusData;
use common::chain::config::ChainConfig;
use common::chain::ConsensusStatus;
use common::primitives::BlockHeight;
use common::primitives::Id;

use crate::detail::pow::work::check_pow_consensus;
use crate::BlockError;

pub(crate) trait BlockIndexHandle {
    fn get_block_index(
        &self,
        block_index: &Id<Block>,
    ) -> blockchain_storage::Result<Option<BlockIndex>>;
    fn get_ancestor(
        &self,
        block_index: &BlockIndex,
        ancestor_height: BlockHeight,
    ) -> Result<BlockIndex, BlockError>;
}

pub(crate) fn validate_consensus(
    chain_config: &ChainConfig,
    block: &Block,
    block_index_handle: &dyn BlockIndexHandle,
) -> Result<(), BlockError> {
    let block_height = if block.is_genesis(chain_config) {
        BlockHeight::from(0)
    } else {
        let prev_block_id =
            block.prev_block_id().expect("Block not genesis so must have a prev_block_id");
        block_index_handle
            .get_block_index(&prev_block_id)?
            .ok_or(BlockError::Orphan)?
            .get_block_height()
            .checked_add(1)
            .expect("max block height reached")
    };
    let consensus_status = chain_config.net_upgrade().consensus_status(block_height);
    do_validate(chain_config, block, &consensus_status, block_index_handle)?;
    Ok(())
}

fn do_validate(
    chain_config: &ChainConfig,
    block: &Block,
    consensus_status: &ConsensusStatus,
    block_index_handle: &dyn BlockIndexHandle,
) -> Result<(), BlockError> {
    let block_consensus_data = block.consensus_data();
    match (block_consensus_data, consensus_status) {
        (_, ConsensusStatus::IgnoreConsensus) => Ok(()),
        (ConsensusData::PoW(..), ConsensusStatus::PoW(pow_status)) => {
            check_pow_consensus(chain_config, block, *pow_status, block_index_handle)
        }
        (block_consensus_data, chain_consensus_status) => Err(BlockError::ConsensusTypeMismatch {
            block_consensus_data: block_consensus_data.clone(),
            chain_consensus_status: *chain_consensus_status,
        }),
    }
}
