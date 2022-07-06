use serialization::{Decode, Encode};

use super::schnorrkel::data::SchnorrkelVRFReturn;

#[must_use]
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub enum VRFReturn {
    Schnorrkel(SchnorrkelVRFReturn),
}

impl From<SchnorrkelVRFReturn> for VRFReturn {
    fn from(r: SchnorrkelVRFReturn) -> Self {
        VRFReturn::Schnorrkel(r)
    }
}
