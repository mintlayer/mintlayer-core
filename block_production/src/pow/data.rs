use common::chain::block::{Block, ConsensusData};
use common::primitives::Compact;

pub struct Data {
    pub bits: Compact,
    pub nonce: u128,
}

impl From<ConsensusData> for Data {
    fn from(_: ConsensusData) -> Self {
        todo!()
    }
}

impl From<Data> for ConsensusData {
    fn from(_: Data) -> Self {
        todo!()
    }
}

pub fn get_bits(block: &Block) -> Compact {
    Data::from(block.get_consensus_data().clone()).bits
}
