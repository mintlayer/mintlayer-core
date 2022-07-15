use crypto::vrf::VRFPublicKey;
use serialization::{Decode, Encode};

use crate::primitives::Amount;

use super::Destination;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct StakePoolData {
    owner: Destination,
    staker: Option<Destination>,
    vrf_public_key: VRFPublicKey,
    // TODO: create a PerThousand type
    #[codec(compact)]
    margin_ratio_per_thousand: u64,
    cost_per_epoch: Amount,
}

impl StakePoolData {
    pub fn owner(&self) -> &Destination {
        &self.owner
    }

    pub fn vrf_public_key(&self) -> &VRFPublicKey {
        &self.vrf_public_key
    }

    pub fn staker(&self) -> &Destination {
        self.staker.as_ref().unwrap_or(&self.owner)
    }

    pub fn is_delegated(&self) -> bool {
        self.staker.is_some()
    }

    pub fn margin_ratio_per_thousand(&self) -> u64 {
        self.margin_ratio_per_thousand
    }

    pub fn cost_per_epoch(&self) -> &Amount {
        &self.cost_per_epoch
    }
}
