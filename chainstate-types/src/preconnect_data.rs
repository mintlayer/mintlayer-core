use serialization::{Decode, Encode};

use crate::stake_modifer::PoSStakeModifier;

#[derive(Debug, Encode, Decode, Clone)]
pub enum ConsensusExtraData {
    None,
    PoS(PoSStakeModifier),
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

    pub fn stake_modifier(&self) -> Option<&PoSStakeModifier> {
        match &self.consensus_extra {
            ConsensusExtraData::None => None,
            ConsensusExtraData::PoS(stake_modifer) => Some(stake_modifer),
        }
    }
}
