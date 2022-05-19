use std::sync::Arc;

use common::{
    chain::block::{Block, BlockHeader},
    primitives::{BlockHeight, Id},
};

use crate::{detail::BlockSource, ConsensusError, ConsensusEvent};

use super::ConsensusInterface;

mockall::mock! {
    pub ConsensusInterfaceMock {}

    impl ConsensusInterface for ConsensusInterfaceMock {
        fn subscribe_to_events(&mut self, handler: Arc<dyn Fn(ConsensusEvent) + Send + Sync>);
        fn process_block(&mut self, block: Block, source: BlockSource) -> Result<(), ConsensusError>;
        fn preliminary_block_check(&self, block: Block) -> Result<(), ConsensusError>;
        fn get_best_block_id(&self) -> Result<Id<Block>, ConsensusError>;
        fn is_block_in_main_chain(&self, block_id: &Id<Block>) -> Result<bool, ConsensusError>;
        fn get_block_height_in_main_chain(
            &self,
            block_id: &Id<Block>,
        ) -> Result<Option<BlockHeight>, ConsensusError>;
        fn get_block_id_from_height(
            &self,
            height: &BlockHeight,
        ) -> Result<Option<Id<Block>>, ConsensusError>;
        fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ConsensusError>;
        fn get_locator(&self) -> Result<Vec<BlockHeader>, ConsensusError>;
        fn get_headers(
            &self,
            locator: Vec<BlockHeader>,
        ) -> Result<Vec<BlockHeader>, ConsensusError>;
        fn get_uniq_headers(
            &self,
            headers: Vec<BlockHeader>,
        ) -> Result<Vec<BlockHeader>, ConsensusError>;
    }
}
