use serialization::{Decode, Encode};

use crate::random::make_true_rng;

mod schnorrkel;

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub enum VRFKeyKind {
    #[codec(index = 0)]
    Schnorrkel,
}

#[must_use]
#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub struct VRFPrivateKey {
    key: VRFPrivateKeyHolder,
}

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub(crate) enum VRFPrivateKeyHolder {
    #[codec(index = 0)]
    Schnorrkel(schnorrkel::SchnorrkelPrivateKey),
}

#[must_use]
#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Decode, Encode)]
pub struct VRFPublicKey {
    pub_key: VRFPublicKeyHolder,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Decode, Encode)]
pub(crate) enum VRFPublicKeyHolder {
    #[codec(index = 0)]
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

#[cfg(test)]
mod tests {
    use hex::FromHex;
    use serialization::DecodeAll;

    use super::*;

    #[test]
    fn key_serialization() {
        let (sk, pk) = VRFPrivateKey::new(VRFKeyKind::Schnorrkel);

        let encoded_sk = sk.encode();
        let encoded_pk = pk.encode();

        let decoded_sk = VRFPrivateKey::decode_all(&mut encoded_sk.as_slice()).unwrap();
        let decoded_pk = VRFPublicKey::decode_all(&mut encoded_pk.as_slice()).unwrap();

        assert_eq!(sk, decoded_sk);
        assert_eq!(pk, decoded_pk);

        let encoded_sk_again = decoded_sk.encode();
        let encoded_pk_again = decoded_pk.encode();

        assert_eq!(encoded_sk, encoded_sk_again);
        assert_eq!(encoded_pk, encoded_pk_again);
    }

    #[test]
    fn fixed_keys() {
        let encoded_sk :Vec<u8> = FromHex::from_hex("00c4546c0ad4d86dff34ff0459737e3bab90a0e3452c6deea6e8701a215ed45b0565d5ecaa1e36e81e5ad2b0fe884ed5d25f1de033d15cfb3ae8fb634ea130f93c").unwrap();
        let encoded_pk: Vec<u8> =
            FromHex::from_hex("006a9602eaae527451eed95667ecd4756324084e46b52fe908283c8b6b69095c09")
                .unwrap();

        let decoded_sk = VRFPrivateKey::decode_all(&mut encoded_sk.as_slice()).unwrap();
        let decoded_pk = VRFPublicKey::decode_all(&mut encoded_pk.as_slice()).unwrap();

        assert_eq!(decoded_pk, VRFPublicKey::from_private_key(&decoded_sk))
    }
}
