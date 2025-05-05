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

use crate::key::hdkd::{
    chain_code::ChainCode, child_number::ChildNumber, derivable::DerivationError,
};
use randomness::{CryptoRng, Rng};
use schnorrkel::{derive::Derivation, Keypair};
use serialization::{Decode, Encode};

use self::data::SchnorrkelVRFReturn;

use super::{primitives::VRFReturn, transcript::traits::SignableTranscript, VRFError};
const PUBKEY_LEN: usize = 32;
const PRIVKEY_LEN: usize = 64; // scalar + nonce

pub mod data;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[must_use]
pub struct SchnorrkelPublicKey {
    key: schnorrkel::PublicKey,
}

impl SchnorrkelPublicKey {
    pub fn from_private_key(private_key: &SchnorrkelPrivateKey) -> Self {
        SchnorrkelPublicKey {
            key: private_key.key.to_public(),
        }
    }

    pub fn verify_generic_vrf_data<T: SignableTranscript>(
        &self,
        message: T,
        vrf_data: &VRFReturn,
    ) -> Result<(), VRFError> {
        match vrf_data {
            VRFReturn::Schnorrkel(d) => self.verify_vrf_data(message, d),
        }
    }

    pub fn verify_vrf_data<T: SignableTranscript>(
        &self,
        message: T,
        vrf_data: &SchnorrkelVRFReturn,
    ) -> Result<(), VRFError> {
        self.key
            .vrf_verify(message, vrf_data.preout(), vrf_data.proof())
            .map_err(|_| VRFError::VerificationError)?;
        Ok(())
    }

    pub fn derive_child(
        &self,
        chain_code: ChainCode,
        child_number: ChildNumber,
    ) -> Result<(Self, ChainCode), DerivationError> {
        if child_number.is_hardened() {
            Err(DerivationError::CannotDeriveHardenedKeyFromPublicKey(
                child_number,
            ))
        } else {
            let (secret_key, new_chain_code) = self.key.derived_key_simple(
                schnorrkel::derive::ChainCode(chain_code.into_array()),
                child_number.into_encoded_be_bytes(),
            );

            Ok((Self { key: secret_key }, new_chain_code.0.into()))
        }
    }
}

impl Encode for SchnorrkelPublicKey {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.key.to_bytes().using_encoded(f)
    }

    fn encoded_size(&self) -> usize {
        debug_assert_eq!(self.key.to_bytes().len(), PUBKEY_LEN);
        PUBKEY_LEN
    }
}

impl Decode for SchnorrkelPublicKey {
    fn encoded_fixed_size() -> Option<usize> {
        Some(PUBKEY_LEN)
    }

    fn decode<I: serialization::Input>(input: &mut I) -> Result<Self, serialization::Error> {
        const ERR_MSG: &str = "Failed to read schnorrkel public key";
        let mut v = [0; PUBKEY_LEN];
        input.read(v.as_mut_slice())?;
        let key = schnorrkel::PublicKey::from_bytes(&v)
            .map_err(|_| serialization::Error::from(ERR_MSG))?;
        Ok(Self { key })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct SchnorrkelPrivateKey {
    key: schnorrkel::SecretKey,
}

impl SchnorrkelPrivateKey {
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> (SchnorrkelPrivateKey, SchnorrkelPublicKey) {
        let sk = schnorrkel::SecretKey::generate_with(rng);
        let pk = sk.to_public();
        let sk = Self { key: sk };
        let pk = SchnorrkelPublicKey { key: pk };
        (sk, pk)
    }

    /// Derive a key from a 32-byte secret
    pub fn new_using_random_bytes(
        bytes: &[u8],
    ) -> Result<(SchnorrkelPrivateKey, SchnorrkelPublicKey), VRFError> {
        let mini_secret = schnorrkel::MiniSecretKey::from_bytes(bytes)
            .map_err(|e| VRFError::GenerateKeyError(e.to_string()))?;
        let keypair = mini_secret.expand_to_keypair(schnorrkel::ExpansionMode::Uniform);
        Ok((
            SchnorrkelPrivateKey {
                key: keypair.secret.clone(),
            },
            SchnorrkelPublicKey {
                key: keypair.public,
            },
        ))
    }

    pub fn produce_vrf_data<T: SignableTranscript>(&self, message: T) -> SchnorrkelVRFReturn {
        let extra = message.make_extra_transcript();
        let (io, proof, _batchable_proof) = Keypair {
            secret: self.key.clone(),
            public: self.key.to_public(),
        }
        .vrf_sign_extra(message, extra);

        SchnorrkelVRFReturn::new(io.to_preout(), proof)
    }

    pub fn derive_child(
        &self,
        chain_code: ChainCode,
        child_number: ChildNumber,
    ) -> (Self, ChainCode) {
        if child_number.is_hardened() {
            let (mini_secret, new_chain_code) = self.key.hard_derive_mini_secret_key(
                Some(schnorrkel::derive::ChainCode(chain_code.into_array())),
                child_number.into_encoded_be_bytes(),
            );

            (
                Self {
                    key: mini_secret.expand(schnorrkel::ExpansionMode::Uniform),
                },
                new_chain_code.0.into(),
            )
        } else {
            let (secret_key, new_chain_code) = self.key.derived_key_simple(
                schnorrkel::derive::ChainCode(chain_code.into_array()),
                child_number.into_encoded_be_bytes(),
            );

            (Self { key: secret_key }, new_chain_code.0.into())
        }
    }
}

impl Encode for SchnorrkelPrivateKey {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.key.to_bytes().using_encoded(f)
    }

    fn encoded_size(&self) -> usize {
        debug_assert_eq!(self.key.to_bytes().len(), PRIVKEY_LEN);
        PRIVKEY_LEN
    }
}

impl Decode for SchnorrkelPrivateKey {
    fn encoded_fixed_size() -> Option<usize> {
        Some(PRIVKEY_LEN)
    }

    fn decode<I: serialization::Input>(input: &mut I) -> Result<Self, serialization::Error> {
        const ERR_MSG: &str = "Failed to read schnorrkel private key";
        let mut v = [0; PRIVKEY_LEN];
        input.read(v.as_mut_slice())?;
        let key = schnorrkel::SecretKey::from_bytes(&v)
            .map_err(|_| serialization::Error::from(ERR_MSG))?;
        Ok(Self { key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;
    use randomness::{make_true_rng, RngCore};
    use schnorrkel::{signing_context, Keypair};
    use serialization::{DecodeAll, Encode};
    use test_utils::random::{make_seedable_rng, Seed};

    #[test]
    fn key_serialization() {
        let mut rng = make_true_rng();
        let (sk, pk) = SchnorrkelPrivateKey::new(&mut rng);

        let encoded_sk = sk.encode();
        let encoded_pk = pk.encode();

        assert_eq!(encoded_sk.len(), PRIVKEY_LEN);
        assert_eq!(encoded_pk.len(), PUBKEY_LEN);

        let decoded_sk = SchnorrkelPrivateKey::decode_all(&mut encoded_sk.as_slice()).unwrap();
        let decoded_pk = SchnorrkelPublicKey::decode_all(&mut encoded_pk.as_slice()).unwrap();

        assert_eq!(sk, decoded_sk);
        assert_eq!(pk, decoded_pk);

        let encoded_sk_again = decoded_sk.encode();
        let encoded_pk_again = decoded_pk.encode();

        assert_eq!(encoded_sk, encoded_sk_again);
        assert_eq!(encoded_pk, encoded_pk_again);
    }

    #[test]
    fn fixed_keys() {
        let encoded_sk: Vec<u8> = FromHex::from_hex("414978f2c626250805d5e036249cccae02d6dca262daa8d7a880617da1eeed023effa71123f8172cd5e45b15c92a17fa143aba6010a741353d4dcbe382ae1944").unwrap();
        let encoded_pk: Vec<u8> =
            FromHex::from_hex("86a720458a04160e17441c3622c41933094d28b06a38632933689ec89fa8fb3c")
                .unwrap();

        let decoded_sk = SchnorrkelPrivateKey::decode_all(&mut encoded_sk.as_slice()).unwrap();
        let decoded_pk = SchnorrkelPublicKey::decode_all(&mut encoded_pk.as_slice()).unwrap();

        assert_eq!(
            decoded_pk,
            SchnorrkelPublicKey::from_private_key(&decoded_sk)
        )
    }

    #[test]
    fn vrf_internal_simple() {
        let mut csprng = make_true_rng();

        let keypair1 = Keypair::generate_with(&mut csprng);

        let ctx = signing_context(b"yoo!");
        let msg = b"meow";
        let (io1, proof1, proof1batchable) = keypair1.vrf_sign(ctx.bytes(msg));
        let out1 = &io1.to_preout();
        assert_eq!(
            proof1,
            proof1batchable.shorten_vrf(&keypair1.public, ctx.bytes(msg), out1).unwrap(),
            "Oops `shorten_vrf` failed"
        );
        let (io1too, proof1too) = keypair1
            .public
            .vrf_verify(ctx.bytes(msg), out1, &proof1)
            .expect("Correct VRF verification failed!");
        assert_eq!(
            io1too, io1,
            "Output differs between signing and verification!"
        );
        assert_eq!(
            proof1batchable, proof1too,
            "VRF verification yielded incorrect batchable proof"
        );
        assert_eq!(
            keypair1.vrf_sign(ctx.bytes(msg)).0,
            io1,
            "Rerunning VRF gave different output"
        );

        assert!(
            keypair1.public.vrf_verify(ctx.bytes(b"not meow"), out1, &proof1).is_err(),
            "VRF verification with incorrect message passed!"
        );

        let keypair2 = Keypair::generate_with(&mut csprng);
        assert!(
            keypair2.public.vrf_verify(ctx.bytes(msg), out1, &proof1).is_err(),
            "VRF verification with incorrect signer passed!"
        );
    }

    #[test]
    fn vrf_from_bytes() {
        // Verify that [SchnorrkelPrivateKey::new_from_bytes] returns the same result to prevent future regressions
        let keys = [
            ("783231456c206e78989c15741764d6c4e7b96e1bac4ea322bfb5df5676876717", "a9246f2ac3b7c3c46bfd903ce077c6033148a13692ccb33a732d9c3616d93a0ca73efa91903bfe5eea90e0d6e684f6e444218baa403aece75c3036a322e845a2"),
            ("c247d6edd1b5e32c0750eeb256ef63186c1a7cebf1729249ae31f65f959aa1ae", "3e16bf35d133fd5ae2b59838cc29847aa040f76f37a0445405bcb9238e3ae1049354882edf8916041d23c2d33cbed8e537a23da5bbf5a432f0c1737253f5c188"),
            ("440acd9f2e1d3e197f745d11c03cd9b805acfb5c5d5f4dfe0d8a55d1d29efa42", "956c30c899065b7b3e085fe50f6431bce7adcc5dbcc114e7c6ad73c148b30c0f85bc02f31c809a173929dec21c8c2380bdc5fe5cfa37f1a6b8b6af9c0ae95515"),
        ];
        for (bytes_hex, expected) in keys {
            let bytes = hex::decode(bytes_hex).unwrap();
            let (sk, _pk) = SchnorrkelPrivateKey::new_using_random_bytes(&bytes).unwrap();
            let expected_sk =
                SchnorrkelPrivateKey::decode_all(&mut hex::decode(expected).unwrap().as_slice())
                    .unwrap();
            assert_eq!(sk, expected_sk, "Unexpected result for {bytes_hex}");
        }
    }

    #[rstest::rstest]
    #[trace]
    #[case(test_utils::random::Seed::from_entropy())]
    fn vrf_from_random_bytes(#[case] seed: Seed) {
        // Check that [SchnorrkelPrivateKey::new_from_bytes] succeeds for all 32 bytes
        let mut rng = make_seedable_rng(seed);
        for _ in 0..10 {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            let (_sk, _pk) = SchnorrkelPrivateKey::new_using_random_bytes(&bytes).unwrap();
        }
    }
}
