// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): S. Afach

use serialization::{Decode, Encode};

use crate::random::make_true_rng;

use self::primitives::VRFReturn;

#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum VRFError {
    #[error("Failed to verify VRF output")]
    VerificationError,
}

mod primitives;
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

    pub fn produce_vrf_data<T: AsRef<[u8]>>(&self, message: T) -> VRFReturn {
        match &self.key {
            VRFPrivateKeyHolder::Schnorrkel(k) => k.produce_vrf(message).into(),
        }
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

    pub fn verify_vrf<T: AsRef<[u8]>>(
        &self,
        message: T,
        vrf_data: &VRFReturn,
    ) -> Result<(), VRFError> {
        match &self.pub_key {
            VRFPublicKeyHolder::Schnorrkel(pub_key) => {
                pub_key.verify_generic_vrf(message, vrf_data)
            }
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

    #[test]
    fn basic_usage() {
        let message = b"Hi there! This is my message to you!";

        let (sk, pk) = VRFPrivateKey::new(VRFKeyKind::Schnorrkel);
        let vrf_data = sk.produce_vrf_data(&message);
        pk.verify_vrf(&message, &vrf_data).expect("Valid VRF check failed");
    }

    #[test]
    fn select_preserialized_data() {
        let message = b"Hi there! This is my message to you!";

        let sk_encoded: Vec<u8> = FromHex::from_hex("006a19dc3c9f5c359602cd0097e4e2b9c1a7536face014ccea7c57aae06b9081039a8319ce360837512e3608701d27ae0fbdafec5e98fb2374f0c276b6888acbda").unwrap();
        let _sk = VRFPrivateKey::decode_all(&mut sk_encoded.as_slice()).unwrap();

        let pk_encoded: Vec<u8> =
            FromHex::from_hex("00c0158e93e3904b404a12f56493802f3a325939fa780dc0fc415370599be27c68")
                .unwrap();
        let pk = VRFPublicKey::decode_all(&mut pk_encoded.as_slice()).unwrap();

        let vrf_data_encoded: Vec<u8> =FromHex::from_hex("0020a63e917e73057b3f3fdad55ceff537f666c1440824a4f4d8a3d0e73cac610a11ce674e1666212263fce00dd9dfd25b16546878f306c30e11f5815efcbfe70b72d60562ae423c928b86af2164830450883630c81987aa3de666b3823c77b507").unwrap();

        let vrf_data = VRFReturn::decode_all(&mut vrf_data_encoded.as_slice()).unwrap();

        pk.verify_vrf(&message, &vrf_data).expect("Valid VRF check failed");
    }
}
