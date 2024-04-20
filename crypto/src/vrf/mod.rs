// Copyright (c) 2021-2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use hmac::{Hmac, Mac};
use serialization::{hex_encoded::HexEncoded, Decode, Encode};
use sha2::Sha512;

use crate::{
    key::hdkd::{
        chain_code::ChainCode,
        child_number::ChildNumber,
        derivable::{Derivable, DerivationError},
        derivation_path::DerivationPath,
    },
    util::{self, new_hmac_sha_512},
};
use randomness::{make_true_rng, CryptoRng, Rng};

pub use self::primitives::VRFReturn;
use self::transcript::traits::SignableTranscript;

#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum VRFError {
    #[error("Failed to verify VRF output")]
    VerificationError,
    #[error("Failed to attach input")]
    InputAttachError(String),
    #[error("Key generation failed: {0}")]
    GenerateKeyError(String),
}

mod primitives;
mod schnorrkel;

pub mod transcript;

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

impl serde::Serialize for VRFPublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        HexEncoded::new(self).serialize(serializer)
    }
}

impl<'d> serde::Deserialize<'d> for VRFPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'d>,
    {
        HexEncoded::<VRFPublicKey>::deserialize(deserializer).map(|hex| hex.take())
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Decode, Encode)]
pub(crate) enum VRFPublicKeyHolder {
    #[codec(index = 0)]
    Schnorrkel(schnorrkel::SchnorrkelPublicKey),
}

impl VRFPrivateKey {
    pub fn new_from_entropy(key_kind: VRFKeyKind) -> (VRFPrivateKey, VRFPublicKey) {
        Self::new_from_rng(&mut make_true_rng(), key_kind)
    }

    pub fn new_from_rng(
        rng: &mut (impl Rng + CryptoRng),
        key_kind: VRFKeyKind,
    ) -> (VRFPrivateKey, VRFPublicKey) {
        match key_kind {
            VRFKeyKind::Schnorrkel => {
                let k = schnorrkel::SchnorrkelPrivateKey::new(rng);
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

    /// This function initializes the key using the bytes safely, but DOES NOT mean that the bytes will be used as the key.
    /// There could be an internal algorithm that does the initialization. The function expects a random sequence of bytes.
    pub fn new_using_random_bytes(
        bytes: &[u8],
        key_kind: VRFKeyKind,
    ) -> Result<(VRFPrivateKey, VRFPublicKey), VRFError> {
        match key_kind {
            VRFKeyKind::Schnorrkel => {
                let k = schnorrkel::SchnorrkelPrivateKey::new_using_random_bytes(bytes)?;
                Ok((
                    VRFPrivateKey {
                        key: VRFPrivateKeyHolder::Schnorrkel(k.0),
                    },
                    VRFPublicKey {
                        pub_key: VRFPublicKeyHolder::Schnorrkel(k.1),
                    },
                ))
            }
        }
    }

    pub fn kind(&self) -> VRFKeyKind {
        match self.key {
            VRFPrivateKeyHolder::Schnorrkel(_) => VRFKeyKind::Schnorrkel,
        }
    }

    pub(crate) fn internal_key(&self) -> &VRFPrivateKeyHolder {
        &self.key
    }

    pub fn produce_vrf_data<T: SignableTranscript>(&self, message: T) -> VRFReturn {
        match &self.key {
            VRFPrivateKeyHolder::Schnorrkel(k) => k.produce_vrf_data(message).into(),
        }
    }

    pub fn to_public_key(&self) -> VRFPublicKey {
        VRFPublicKey::from_private_key(self)
    }
}

impl VRFPublicKey {
    pub fn from_private_key(private_key: &VRFPrivateKey) -> Self {
        match private_key.internal_key() {
            VRFPrivateKeyHolder::Schnorrkel(ref k) => VRFPublicKey {
                pub_key: VRFPublicKeyHolder::Schnorrkel(
                    schnorrkel::SchnorrkelPublicKey::from_private_key(k),
                ),
            },
        }
    }

    pub fn verify_vrf_data<T: SignableTranscript>(
        &self,
        message: T,
        vrf_data: &VRFReturn,
    ) -> Result<(), VRFError> {
        match &self.pub_key {
            VRFPublicKeyHolder::Schnorrkel(pub_key) => {
                pub_key.verify_generic_vrf_data(message, vrf_data)
            }
        }
    }
}

/// Given a tree of keys that are derived from a master key using BIP32 rules, this struct represents
/// the private key at one of the nodes of this tree.
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct ExtendedVRFPrivateKey {
    /// The absolute derivation path that was used to derive this key
    derivation_path: DerivationPath,
    /// The chain code is used in BIP32 in conjunction with the private key to allow derivation
    /// of child keys
    chain_code: ChainCode,
    /// The private key to be used to derive child keys of this node using BIP32 rules
    private_key: VRFPrivateKey,
}

impl ExtendedVRFPrivateKey {
    pub fn new_master(
        seed: &[u8],
        keykind: VRFKeyKind,
    ) -> Result<ExtendedVRFPrivateKey, DerivationError> {
        // Create a new mac with the appropriate BIP32 constant
        // Have a different constant from the Secp256k1 so that in case it is leaked the VRF key
        // will remain safe
        let mut mac = new_hmac_sha_512(b"Bitcoin VRF seed");

        mac.update(seed);

        let (private_key, chain_code) = to_key_and_chain_code(mac, keykind)?;

        Ok(ExtendedVRFPrivateKey {
            derivation_path: DerivationPath::empty(),
            private_key,
            chain_code,
        })
    }

    pub fn private_key(self) -> VRFPrivateKey {
        self.private_key
    }

    pub fn to_public_key(&self) -> ExtendedVRFPublicKey {
        ExtendedVRFPublicKey::from_private_key(self)
    }
}

impl Derivable for ExtendedVRFPrivateKey {
    fn derive_child(self, num: ChildNumber) -> Result<Self, DerivationError> {
        match self.private_key.key {
            VRFPrivateKeyHolder::Schnorrkel(key) => {
                let (private_key, chain_code) = key.derive_child(self.chain_code, num);
                let new_derivaton_path = {
                    let mut child_path = self.derivation_path.into_vec();
                    child_path.push(num);
                    child_path.try_into()?
                };
                Ok(ExtendedVRFPrivateKey {
                    private_key: VRFPrivateKey {
                        key: VRFPrivateKeyHolder::Schnorrkel(private_key),
                    },
                    chain_code,
                    derivation_path: new_derivaton_path,
                })
            }
        }
    }

    fn get_derivation_path(&self) -> &DerivationPath {
        &self.derivation_path
    }
}

/// Given a tree of keys that are derived from a master key using BIP32 rules, this struct represents
/// the public key at one of the nodes of this tree.
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct ExtendedVRFPublicKey {
    /// The absolute derivation path that was used to derive this key
    derivation_path: DerivationPath,
    /// The chain code is used in BIP32 in conjunction with the private key to allow derivation
    /// of child keys
    chain_code: ChainCode,
    /// The public key to be used to derive child keys of this node using BIP32 rules
    public_key: VRFPublicKey,
}

impl ExtendedVRFPublicKey {
    pub fn from_private_key(private_key: &ExtendedVRFPrivateKey) -> Self {
        Self {
            derivation_path: private_key.derivation_path.clone(),
            chain_code: private_key.chain_code,
            public_key: private_key.private_key.to_public_key(),
        }
    }

    pub fn public_key(&self) -> &VRFPublicKey {
        &self.public_key
    }

    pub fn into_public_key(self) -> VRFPublicKey {
        self.public_key
    }
}

impl Derivable for ExtendedVRFPublicKey {
    fn derive_child(self, num: ChildNumber) -> Result<Self, DerivationError> {
        match self.public_key.pub_key {
            VRFPublicKeyHolder::Schnorrkel(key) => {
                let (public_key, chain_code) = key.derive_child(self.chain_code, num)?;
                let new_derivaton_path = {
                    let mut child_path = self.derivation_path.into_vec();
                    child_path.push(num);
                    child_path.try_into()?
                };
                Ok(Self {
                    public_key: VRFPublicKey {
                        pub_key: VRFPublicKeyHolder::Schnorrkel(public_key),
                    },
                    chain_code,
                    derivation_path: new_derivaton_path,
                })
            }
        }
    }

    fn get_derivation_path(&self) -> &DerivationPath {
        &self.derivation_path
    }
}

fn to_key_and_chain_code(
    mac: Hmac<Sha512>,
    key_kind: VRFKeyKind,
) -> Result<(VRFPrivateKey, ChainCode), DerivationError> {
    util::to_key_and_chain_code(mac, |secret_key_bytes| {
        VRFPrivateKey::new_using_random_bytes(secret_key_bytes, key_kind)
            .map(|(prv, _pub)| prv)
            .map_err(|_| DerivationError::KeyDerivationError)
    })
}

#[cfg(test)]
mod tests {
    use hex::FromHex;
    use rstest::rstest;
    use serialization::DecodeAll;
    use test_utils::random::make_seedable_rng;
    use test_utils::random::Seed;

    use self::transcript::no_rng::VRFTranscript;

    use super::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn key_serialization(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let (sk, pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

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

    fn make_arbitrary_transcript() -> VRFTranscript {
        VRFTranscript::new(b"some context")
            .attach_raw_data(b"some label", b"Data to commit")
            .attach_u64(b"some other label", 42)
            .attach_raw_data(b"some third label", b"More data to commit")
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn vrf_basic_usage(#[case] seed: Seed) {
        let transcript = make_arbitrary_transcript();

        let mut rng = make_seedable_rng(seed);
        let (sk, pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let vrf_data = sk.produce_vrf_data(transcript.clone());

        match &vrf_data {
            VRFReturn::Schnorrkel(d) => {
                assert_eq!(d.vrf_preout().len(), 32);
                assert_eq!(d.vrf_proof().len(), 64);

                let _output_value_to_use_in_application: [u8; 32] = d
                    .calculate_vrf_output_with_generic_key::<generic_array::typenum::U32, _>(
                        pk.clone(),
                        transcript.clone(),
                    )
                    .unwrap()
                    .into();
            }
        }

        pk.verify_vrf_data(transcript, &vrf_data).expect("Valid VRF check failed");
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn basic_usage_schonorrkel_mutated_message(#[case] seed: Seed) {
        let transcript = make_arbitrary_transcript();

        let mut rng = make_seedable_rng(seed);
        let (sk, pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let vrf_data = sk.produce_vrf_data(transcript.clone());

        match &vrf_data {
            VRFReturn::Schnorrkel(d) => {
                assert_eq!(d.vrf_preout().len(), 32);
                assert_eq!(d.vrf_proof().len(), 64);

                let _output_value_to_use_in_application: [u8; 32] = d
                    .calculate_vrf_output_with_generic_key::<generic_array::typenum::U32, _>(
                        pk.clone(),
                        transcript.clone(),
                    )
                    .unwrap()
                    .into();
            }
        }

        let mutated_transcript = transcript;
        let mutated_transcript = mutated_transcript.attach_u64(b"Forgery", 1337);

        pk.verify_vrf_data(mutated_transcript, &vrf_data)
            .expect_err("Invalid VRF check succeeded");
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn basic_usage_schnorrkel_invalid_keys(#[case] seed: Seed) {
        let transcript = make_arbitrary_transcript();

        let mut rng = make_seedable_rng(seed);
        let (sk, pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let vrf_data = sk.produce_vrf_data(transcript.clone());

        match &vrf_data {
            VRFReturn::Schnorrkel(d) => {
                assert_eq!(d.vrf_preout().len(), 32);
                assert_eq!(d.vrf_proof().len(), 64);

                let _output_value_to_use_in_application: [u8; 32] = d
                    .calculate_vrf_output_with_generic_key::<generic_array::typenum::U32, _>(
                        pk,
                        transcript.clone(),
                    )
                    .unwrap()
                    .into();
            }
        }

        let (_sk2, pk2) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

        pk2.verify_vrf_data(transcript, &vrf_data)
            .expect_err("Invalid VRF check succeeded");
    }

    #[test]
    fn select_preserialized_data() {
        let transcript = make_arbitrary_transcript();

        let sk_encoded: Vec<u8> = FromHex::from_hex("006a19dc3c9f5c359602cd0097e4e2b9c1a7536face014ccea7c57aae06b9081039a8319ce360837512e3608701d27ae0fbdafec5e98fb2374f0c276b6888acbda").unwrap();
        let _sk = VRFPrivateKey::decode_all(&mut sk_encoded.as_slice()).unwrap();

        let pk_encoded: Vec<u8> =
            FromHex::from_hex("00c0158e93e3904b404a12f56493802f3a325939fa780dc0fc415370599be27c68")
                .unwrap();
        let pk = VRFPublicKey::decode_all(&mut pk_encoded.as_slice()).unwrap();

        let vrf_data_encoded: Vec<u8> =FromHex::from_hex("00b47d375948c65a57e9782f9ac05e6d66a2364ff0d8a9a2a155447bd439121f3d0749e9b767eec9d50235927519c8f5c5623d49300d5f418d2a91beb71308a50717ea059a9b90055af7eb700ea09307e5db368153e53d91da46f3df513e51270c").unwrap();

        let vrf_data = VRFReturn::decode_all(&mut vrf_data_encoded.as_slice()).unwrap();

        match &vrf_data {
            VRFReturn::Schnorrkel(d) => {
                assert_eq!(d.vrf_preout().len(), 32);
                assert_eq!(d.vrf_proof().len(), 64);

                let _output_value_to_use_in_application: [u8; 32] = d
                    .calculate_vrf_output_with_generic_key::<generic_array::typenum::U32, _>(
                        pk.clone(),
                        transcript.clone(),
                    )
                    .unwrap()
                    .into();
            }
        }

        pk.verify_vrf_data(transcript, &vrf_data).expect("Valid VRF check failed");
    }
}
