use crypto::vrf::VRFPublicKey;
use serialization::{Decode, Encode};

use super::Destination;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct LockedStakeData {
    owner: Destination,
    staker: Option<Destination>,
    vrf_public_key: VRFPublicKey,
}

impl LockedStakeData {
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
}
