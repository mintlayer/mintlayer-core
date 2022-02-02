use crate::pow::temp::BlockIndex;
use common::chain::block::Block;
use common::chain::config::ChainType;
use common::primitives::BlockHeight;

mod config;
mod constants;
mod helpers;
mod temp;
mod work;

pub enum Error {
    BlockToMineError(String),
    ConversionError(String),
}

pub struct PoW;

impl PoW {
    pub fn start(
        mut block: Block,
        max_nonce: u128,
        time: u32,
        prev_block_index: &BlockIndex,
        height: BlockHeight,
        chain_type: ChainType,
    ) -> Result<Block, Error> {
        let bits = work::check_for_work_required(time, prev_block_index, height, chain_type)?;

        work::mine(&mut block, max_nonce, bits)?;

        Ok(block)
    }
}
