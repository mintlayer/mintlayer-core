use super::schnorrkel::data::SchnorrkelVRFReturn;

pub enum VRFReturn {
    Schnorrkel(SchnorrkelVRFReturn),
}

impl From<SchnorrkelVRFReturn> for VRFReturn {
    fn from(r: SchnorrkelVRFReturn) -> Self {
        VRFReturn::Schnorrkel(r)
    }
}
