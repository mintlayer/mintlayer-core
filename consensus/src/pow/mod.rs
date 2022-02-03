pub use crate::pow::config::Config as PoWConfig;
use crate::pow::temp::BlockIndex;
use common::chain::block::Block;
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

impl PoWConfig {
    pub fn start(
        &self,
        mut block: Block,
        time: u32,
        prev_block_index: &BlockIndex,
        height: BlockHeight,
        max_nonce: u128,
    ) -> Result<Block, Error> {
        let bits = self.check_for_work_required(time, prev_block_index, height)?;

        work::mine(&mut block, max_nonce, bits)?;

        Ok(block)
    }
}
