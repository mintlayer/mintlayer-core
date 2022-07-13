use crypto::vrf::VRFPublicKey;
use serialization::{Decode, Encode};

use super::Destination;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct LockedStakeData {
    owner: Destination,
    vrf_public_key: VRFPublicKey,
}

impl LockedStakeData {
    pub fn owner(&self) -> &Destination {
        &self.owner
    }

    pub fn vrf_public_key(&self) -> &VRFPublicKey {
        &self.vrf_public_key
    }
}
