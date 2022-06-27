use chainstate_types::preconnect_data::ConsensusExtraData;
use chainstate_types::stake_modifer::PoSStakeModifier;
use common::chain::block::BlockHeader;
use common::chain::block::ConsensusData;
use common::chain::config::ChainConfig;
use common::chain::PoWStatus;
use common::chain::RequiredConsensus;
use common::primitives::BlockHeight;
use common::primitives::Idable;

use crate::detail::pow::work::check_pow_consensus;
use crate::BlockError;

pub use self::block_index_handle::BlockIndexHandle;
pub use self::transaction_index_handle::TransactionIndexHandle;

use super::ConsensusVerificationError;

mod block_index_handle;
mod transaction_index_handle;

pub(crate) fn validate_consensus<H: BlockIndexHandle>(
    chain_config: &ChainConfig,
    header: &BlockHeader,
    block_index_handle: &H,
) -> Result<(), ConsensusVerificationError> {
    let block_height = if header.is_genesis(chain_config) {
        BlockHeight::from(0)
    } else {
        let prev_block_id = header
            .prev_block_id()
            .clone()
            .expect("Block not genesis so must have a prev_block_id");

        let prev_block_index = match block_index_handle.get_block_index(&prev_block_id) {
            Ok(bi) => bi,
            Err(err) => {
                return Err(ConsensusVerificationError::PrevBlockLoadError(
                    prev_block_id,
                    header.get_id(),
                    err,
                ))
            }
        };

        prev_block_index
            .ok_or_else(|| {
                ConsensusVerificationError::PrevBlockNotFound(prev_block_id, header.get_id())
            })?
            .block_height()
            .checked_add(1)
            .expect("max block height reached")
    };
    let consensus_status = chain_config.net_upgrade().consensus_status(block_height);
    do_validate(chain_config, header, &consensus_status, block_index_handle)?;
    Ok(())
}

fn compute_extra_consensus_data(header: &BlockHeader) -> Result<ConsensusExtraData, BlockError> {
    match header.consensus_data() {
        ConsensusData::None => Ok(ConsensusExtraData::None),
        ConsensusData::PoW(_) => Ok(ConsensusExtraData::None),
        ConsensusData::PoS(pos_data) => {
            let kernel_output = pos_data
                .kernel_inputs()
                .get(0)
                .ok_or(BlockError::PoSKernelInputNotFound(header.get_id()))?;
            // TODO: define prev_stake_modifier in next line
            todo!();
            let stake_modifier = PoSStakeModifier::from_new_block(None, &kernel_output.outpoint());
            let data = ConsensusExtraData::PoS(stake_modifier);
            Ok(data)
        }
    }
}

fn validate_pow_consensus<H: BlockIndexHandle>(
    chain_config: &ChainConfig,
    header: &BlockHeader,
    pow_status: &PoWStatus,
    block_index_handle: &H,
) -> Result<(), ConsensusVerificationError> {
    match header.consensus_data() {
        ConsensusData::None | ConsensusData::PoS(_) => {
            Err(ConsensusVerificationError::ConsensusTypeMismatch(
                "Chain configuration says we are PoW but block consensus data is not PoW.".into(),
            ))
        }
        ConsensusData::PoW(_) => {
            check_pow_consensus(chain_config, header, pow_status, block_index_handle)
                .map_err(ConsensusVerificationError::PoWError)
        }
    }
}

fn validate_ignore_consensus(header: &BlockHeader) -> Result<(), ConsensusVerificationError> {
    match header.consensus_data() {
        ConsensusData::None => Ok(()),
        ConsensusData::PoW(_)|ConsensusData::PoS(_) => Err(ConsensusVerificationError::ConsensusTypeMismatch(
            "Chain configuration says consensus should be empty but block consensus data is not `None`.".into(),
        )),
    }
}

fn validate_pos_consensus(header: &BlockHeader) -> Result<(), ConsensusVerificationError> {
    match header.consensus_data() {
        ConsensusData::None | ConsensusData::PoW(_)=>  Err(ConsensusVerificationError::ConsensusTypeMismatch(
            "Chain configuration says consensus should be empty but block consensus data is not `None`.".into(),
        )),
        ConsensusData::PoS(_) => Ok(()),
    }
}

fn do_validate<H: BlockIndexHandle>(
    chain_config: &ChainConfig,
    header: &BlockHeader,
    consensus_status: &RequiredConsensus,
    block_index_handle: &H,
) -> Result<(), ConsensusVerificationError> {
    match consensus_status {
        RequiredConsensus::PoW(pow_status) => {
            validate_pow_consensus(chain_config, header, pow_status, block_index_handle)
        }
        RequiredConsensus::IgnoreConsensus => validate_ignore_consensus(header),
        RequiredConsensus::PoS => validate_pos_consensus(header),
        RequiredConsensus::DSA => Err(ConsensusVerificationError::UnsupportedConsensusType),
    }
}
