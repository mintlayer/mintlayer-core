use common::chain::block::Block;
use common::chain::block::BlockHeader;
use common::chain::block::BlockIndex;
use common::chain::block::ConsensusData;
use common::chain::config::ChainConfig;
use common::chain::PoWStatus;
use common::chain::RequiredConsensus;
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

pub(crate) fn validate_consensus<H: BlockIndexHandle>(
    chain_config: &ChainConfig,
    header: &BlockHeader,
    block_index_handle: &H,
) -> Result<(), BlockError> {
    let block_height = if header.is_genesis(chain_config) {
        BlockHeight::from(0)
    } else {
        let prev_block_id = header
            .get_prev_block_id()
            .clone()
            .expect("Block not genesis so must have a prev_block_id");
        block_index_handle
            .get_block_index(&prev_block_id)?
            .ok_or(BlockError::IllegalOrphan)?
            .get_block_height()
            .checked_add(1)
            .expect("max block height reached")
    };
    let consensus_status = chain_config.net_upgrade().consensus_status(block_height);
    do_validate(chain_config, header, &consensus_status, block_index_handle)?;
    Ok(())
}

fn validate_pow_consensus<H: BlockIndexHandle>(
    chain_config: &ChainConfig,
    header: &BlockHeader,
    pow_status: &PoWStatus,
    block_index_handle: &H,
) -> Result<(), BlockError> {
    match header.consensus_data() {
        ConsensusData::None | ConsensusData::FakePoS(_) => Err(BlockError::ConsensusTypeMismatch(
            "Chain configuration says we are PoW but block consensus data is not PoW.".into(),
        )),
        ConsensusData::PoW(_) => {
            check_pow_consensus(chain_config, header, pow_status, block_index_handle)
        }
    }
}

fn validate_ignore_consensus(header: &BlockHeader) -> Result<(), BlockError> {
    match header.consensus_data() {
        ConsensusData::None => Ok(()),
        ConsensusData::PoW(_)|ConsensusData::FakePoS(_) => Err(BlockError::ConsensusTypeMismatch(
            "Chain configuration says consensus should be empty but block consensus data is not `None`.".into(),
        )),
    }
}

fn validate_pos_consensus(header: &BlockHeader) -> Result<(), BlockError> {
    match header.consensus_data() {
        ConsensusData::None | ConsensusData::PoW(_)=>  Err(BlockError::ConsensusTypeMismatch(
            "Chain configuration says consensus should be empty but block consensus data is not `None`.".into(),
        )),
        ConsensusData::FakePoS(_) => Ok(()),
    }
}

fn do_validate<H: BlockIndexHandle>(
    chain_config: &ChainConfig,
    header: &BlockHeader,
    consensus_status: &RequiredConsensus,
    block_index_handle: &H,
) -> Result<(), BlockError> {
    match consensus_status {
        RequiredConsensus::PoW(pow_status) => {
            validate_pow_consensus(chain_config, header, pow_status, block_index_handle)
        }
        RequiredConsensus::IgnoreConsensus => validate_ignore_consensus(header),
        RequiredConsensus::PoS => validate_pos_consensus(header),
        RequiredConsensus::DSA => Err(BlockError::UnsupportedConsensusType),
    }
}
