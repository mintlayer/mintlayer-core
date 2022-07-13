use crypto::vrf::VRFPublicKey;
use serialization::{Decode, Encode};

use super::Destination;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct LockedStateData {
    owner: Destination,
    vrf_public_key: VRFPublicKey,
}

impl LockedStateData {
    pub fn owner(&self) -> &Destination {
        &self.owner
    }

    pub fn vrf_public_key(&self) -> &VRFPublicKey {
        &self.vrf_public_key
    }
}
