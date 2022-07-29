use serialization::{Decode, Encode};

use crate::pos_randomness::PoSRandomness;

#[derive(Debug, Encode, Decode, Clone)]
pub enum ConsensusExtraData {
    None,
    PoS(PoSRandomness),
}

#[derive(Debug, Encode, Decode, Clone)]
pub struct BlockPreconnectData {
    consensus_extra: ConsensusExtraData,
}

impl BlockPreconnectData {
    pub fn new(consensus_extra: ConsensusExtraData) -> Self {
        Self { consensus_extra }
    }

    pub fn consensus_extra_data(&self) -> &ConsensusExtraData {
        &self.consensus_extra
    }

    pub fn pos_randomness(&self) -> Option<&PoSRandomness> {
        match &self.consensus_extra {
            ConsensusExtraData::None => None,
            ConsensusExtraData::PoS(randomness) => Some(randomness),
        }
    }
}
