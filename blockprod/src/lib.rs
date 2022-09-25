use std::sync::Arc;

use chainstate::ChainstateHandle;
use common::{chain::ChainConfig, time_getter::TimeGetter};
use detail::BlockProduction;
use interface::BlockProductionInterface;
use mempool::MempoolHandle;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum BlockProductionError {
    #[error("Initialization error")]
    FailedToInitializeBlockProduction(String),
}

mod detail;
pub mod interface;

impl subsystem::Subsystem for Box<dyn BlockProductionInterface> {}

#[allow(dead_code)]
type BlockProductionHandle = subsystem::Handle<Box<dyn BlockProductionInterface>>;

pub fn make_blockproduction(
    _chain_config: Arc<ChainConfig>,
    // blockprod_config: BlockProductionConfig,
    _chainstate_handle: ChainstateHandle,
    _mempool_handle: MempoolHandle,
    _time_getter: TimeGetter,
) -> Result<Box<dyn BlockProductionInterface>, BlockProductionError> {
    Ok(Box::new(BlockProduction::new()))
}
