use serialization::{Decode, Encode};

use crate::random::make_true_rng;

mod schnorrkel;

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub enum VRFKeyKind {
    Schnorrkel,
}

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub struct VRFPrivateKey {
    key: VRFPrivateKeyHolder,
}

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub(crate) enum VRFPrivateKeyHolder {
    Schnorrkel(schnorrkel::SchnorrkelPrivateKey),
}

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Decode, Encode)]
pub struct VRFPublicKey {
    pub_key: VRFPublicKeyHolder,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Decode, Encode)]
pub(crate) enum VRFPublicKeyHolder {
    Schnorrkel(schnorrkel::SchnorrkelPublicKey),
}

impl VRFPrivateKey {
    pub fn new(key_kind: VRFKeyKind) -> (VRFPrivateKey, VRFPublicKey) {
        let mut rng = make_true_rng();
        match key_kind {
            VRFKeyKind::Schnorrkel => {
                let k = schnorrkel::SchnorrkelPrivateKey::new(&mut rng);
                (
                    VRFPrivateKey {
                        key: VRFPrivateKeyHolder::Schnorrkel(k.0),
                    },
                    VRFPublicKey {
                        pub_key: VRFPublicKeyHolder::Schnorrkel(k.1),
                    },
                )
            }
        }
    }

    pub fn kind(&self) -> VRFKeyKind {
        match self.key {
            VRFPrivateKeyHolder::Schnorrkel(_) => VRFKeyKind::Schnorrkel,
        }
    }

    pub(crate) fn get_internal_key(&self) -> &VRFPrivateKeyHolder {
        &self.key
    }
}

impl VRFPublicKey {
    pub fn from_private_key(private_key: &VRFPrivateKey) -> Self {
        match private_key.get_internal_key() {
            VRFPrivateKeyHolder::Schnorrkel(ref k) => VRFPublicKey {
                pub_key: VRFPublicKeyHolder::Schnorrkel(
                    schnorrkel::SchnorrkelPublicKey::from_private_key(k),
                ),
            },
        }
    }
}
