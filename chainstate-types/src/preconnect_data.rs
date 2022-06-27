use serialization::{Decode, Encode};

use crate::stake_modifer::PoSStakeModifier;

#[derive(Encode, Decode, Clone)]
pub enum ConsensusExtraData {
    None,
    PoS(PoSStakeModifier),
}

#[derive(Encode, Decode, Clone)]
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
}
