use crate::interface::BlockProductionInterface;

pub struct BlockProduction {}

impl BlockProduction {
    pub const fn new() -> Self {
        Self {}
    }
}

impl BlockProductionInterface for BlockProduction {}
