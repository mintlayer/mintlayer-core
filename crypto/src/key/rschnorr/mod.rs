// Copyright (c) 2022 RBB S.r.l
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

mod internal;

use crate::random::{CryptoRng, Rng};
use generic_array::GenericArray;
pub use internal::add_sigs;
pub use internal::RistrettoSchnorrSignature;
use internal::*;
use serialization::{Decode, Encode};
use tari_crypto::{keys::PublicKey, tari_utilities::ByteArray};

use crate::hash::{Blake2b32Stream, StreamHasher};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum RistrettoKeyError {
    InvalidData,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum RistrettoSignatureError {
    ByteConversionError(String),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MLRistrettoPrivateKey {
    key_data: RistrettoSecretKey,
}

impl Encode for MLRistrettoPrivateKey {
    fn encode(&self) -> Vec<u8> {
        self.key_data.as_bytes().encode()
    }

    fn encoded_size(&self) -> usize {
        self.key_data.as_bytes().encoded_size()
    }

    fn encode_to<T: serialization::Output + ?Sized>(&self, dest: &mut T) {
        self.key_data.as_bytes().encode_to(dest)
    }

    fn size_hint(&self) -> usize {
        self.key_data.as_bytes().size_hint()
    }

    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.key_data.as_bytes().using_encoded(f)
    }
}

impl Decode for MLRistrettoPrivateKey {
    fn decode<I: serialization::Input>(input: &mut I) -> Result<Self, serialization::Error> {
        let v = Vec::decode(input)?;
        RistrettoSecretKey::from_bytes(&v)
            .map(|r| MLRistrettoPrivateKey { key_data: r })
            .map_err(|_| serialization::Error::from("Private Key deserialization failed"))
    }
}

impl MLRistrettoPrivateKey {
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> (MLRistrettoPrivateKey, MLRistrettoPublicKey) {
        let pair = RistrettoPublicKey::random_keypair(rng);
        (
            MLRistrettoPrivateKey::from_native(pair.0),
            MLRistrettoPublicKey::from_native(pair.1),
        )
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.key_data.as_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RistrettoKeyError> {
        let sk =
            RistrettoSecretKey::from_bytes(bytes).map_err(|_| RistrettoKeyError::InvalidData)?;
        let result = Self::from_native(sk);
        Ok(result)
    }

    pub fn as_native(&self) -> &RistrettoSecretKey {
        &self.key_data
    }

    pub fn from_native(native: RistrettoSecretKey) -> Self {
        Self { key_data: native }
    }

    pub fn construct_challenge_from_message(
        msg: &[u8],
    ) -> GenericArray<u8, generic_array::typenum::U32> {
        Blake2b32Stream::new().write(msg).finalize()
    }

    pub(crate) fn sign_message<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<RistrettoSchnorrSignature, RistrettoSignatureError> {
        let (r, r_pub) = RistrettoPublicKey::random_keypair(rng);
        let k = &self.key_data;
        let e = Self::construct_challenge_from_message(msg);
        let sig = RistrettoSchnorr::sign(k.clone(), r, &e).expect("signing failed");
        debug_assert_eq!(*sig.get_public_nonce(), r_pub);
        Ok(sig)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct MLRistrettoPublicKey {
    pubkey_data: RistrettoPublicKey,
}

impl Encode for MLRistrettoPublicKey {
    fn encode(&self) -> Vec<u8> {
        self.pubkey_data.as_bytes().encode()
    }

    fn encoded_size(&self) -> usize {
        self.pubkey_data.as_bytes().encoded_size()
    }

    fn encode_to<T: serialization::Output + ?Sized>(&self, dest: &mut T) {
        self.pubkey_data.as_bytes().encode_to(dest)
    }

    fn size_hint(&self) -> usize {
        self.pubkey_data.as_bytes().size_hint()
    }

    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.pubkey_data.as_bytes().using_encoded(f)
    }
}

impl Decode for MLRistrettoPublicKey {
    fn decode<I: serialization::Input>(input: &mut I) -> Result<Self, serialization::Error> {
        let v = Vec::decode(input)?;
        RistrettoPublicKey::from_bytes(&v)
            .map(|r| MLRistrettoPublicKey { pubkey_data: r })
            .map_err(|_| serialization::Error::from("Public Key deserialization failed"))
    }
}

impl MLRistrettoPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        self.pubkey_data.as_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RistrettoKeyError> {
        let pk =
            RistrettoPublicKey::from_bytes(bytes).map_err(|_| RistrettoKeyError::InvalidData)?;
        let result = Self::from_native(pk);
        Ok(result)
    }

    pub fn as_native(&self) -> &RistrettoPublicKey {
        &self.pubkey_data
    }

    pub fn from_native(native: RistrettoPublicKey) -> Self {
        Self {
            pubkey_data: native,
        }
    }

    pub fn from_private_key(private_key: &MLRistrettoPrivateKey) -> Self {
        Self::from_native(RistrettoPublicKey::from_secret_key(&private_key.key_data))
    }

    #[allow(unused)]
    pub(crate) fn verify_challenge(
        &self,
        signature: &RistrettoSchnorrSignature,
        challenge: &[u8],
    ) -> bool {
        signature.verify_challenge(self.as_native(), challenge)
    }

    pub(crate) fn verify_message(&self, signature: &RistrettoSchnorrSignature, msg: &[u8]) -> bool {
        let e = Blake2b32Stream::new().write(msg).finalize();
        signature.verify_challenge(self.as_native(), &e)
    }
}

impl std::ops::Add for &MLRistrettoPublicKey {
    type Output = MLRistrettoPublicKey;
    fn add(self, rhs: Self) -> MLRistrettoPublicKey {
        let result = self.as_native() + rhs.as_native();
        MLRistrettoPublicKey::from_native(result)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::random::make_true_rng;
    use hex::ToHex;
    use serialization::DecodeAll;
    use tari_crypto::tari_utilities::message_format::MessageFormat;

    #[test]
    fn basic() {
        let mut rng = make_true_rng();
        let (sk, pk) = MLRistrettoPrivateKey::new(&mut rng);
        let pk2 = MLRistrettoPublicKey::from_private_key(&sk);
        assert_eq!(pk, pk2);
    }

    #[test]
    fn import_from_short_key() {
        let mut rng = make_true_rng();
        let (sk, pk) = MLRistrettoPrivateKey::new(&mut rng);
        {
            let sk_bytes = sk.as_bytes();
            let sk_short = &sk_bytes[..sk_bytes.len() - 1];
            assert_eq!(sk_short.len(), 31);
            let sk_again = MLRistrettoPrivateKey::from_bytes(sk_short);
            assert!(sk_again.is_err());
        }
        {
            let pk_bytes = pk.as_bytes();
            let pk_short = &pk_bytes[..pk_bytes.len() - 1];
            assert_eq!(pk_short.len(), 31);
            let pk_again = MLRistrettoPublicKey::from_bytes(pk_short);
            assert!(pk_again.is_err());
        }
    }

    #[test]
    fn serialize() {
        let mut rng = make_true_rng();
        let (sk, pk) = MLRistrettoPrivateKey::new(&mut rng);
        let sk_encoded = sk.encode();
        let pk_encoded = pk.encode();
        let sk2 = MLRistrettoPrivateKey::decode_all(&mut sk_encoded.as_slice()).unwrap();
        let pk2 = MLRistrettoPublicKey::decode_all(&mut pk_encoded.as_slice()).unwrap();
        assert_eq!(sk, sk2);
        assert_eq!(pk, pk2);
    }

    #[test]
    fn serialize_chosen_data() {
        let sk = RistrettoSecretKey::from_base64(
            "IAAAAAAAAAC46tzI9UVS8WiNtYENaQbUWW58Ti7SHPdLrNsicPZiAQ==",
        )
        .unwrap();
        let pk = RistrettoPublicKey::from_base64(
            "IAAAAAAAAAAqODDr/WZY9yAdMzAZSrv6+APxs2SHbeUYxh+e26mVJg==",
        )
        .unwrap();

        let sk = MLRistrettoPrivateKey::from_native(sk);
        let pk = MLRistrettoPublicKey::from_native(pk);

        let sk_encoded = sk.encode();
        let pk_encoded = pk.encode();

        assert_eq!(
            sk_encoded.encode_hex::<String>(),
            "80b8eadcc8f54552f1688db5810d6906d4596e7c4e2ed21cf74bacdb2270f66201"
        );
        assert_eq!(
            pk_encoded.encode_hex::<String>(),
            "802a3830ebfd6658f7201d3330194abbfaf803f1b364876de518c61f9edba99526"
        );

        let sk2 = MLRistrettoPrivateKey::decode_all(&mut sk_encoded.as_slice()).unwrap();
        let pk2 = MLRistrettoPublicKey::decode_all(&mut pk_encoded.as_slice()).unwrap();
        assert_eq!(sk, sk2);
        assert_eq!(pk, pk2);
    }

    #[test]
    fn sign_and_verify() {
        let mut rng = make_true_rng();
        let msg_size = 1 + rand::random::<usize>() % 10000;
        let msg: Vec<u8> = (0..msg_size).map(|_| rand::random::<u8>()).collect();
        let (sk, pk) = MLRistrettoPrivateKey::new(&mut rng);
        let sig = sk.sign_message(&mut rng, &msg).unwrap();
        assert!(pk.verify_message(&sig, &msg));
    }

    #[test]
    fn sign_empty() {
        let mut rng = make_true_rng();
        let msg: Vec<u8> = Vec::new();
        let (sk, pk) = MLRistrettoPrivateKey::new(&mut rng);
        let sig = sk.sign_message(&mut rng, &msg).unwrap();
        assert!(pk.verify_message(&sig, &msg));
    }

    #[test]
    fn sk_zeroed() {
        use std::slice;
        let mut rng = make_true_rng();
        let zero_sk = &vec![0u8; 32][..];
        let hldr;
        {
            let (sk, _pk) = MLRistrettoPrivateKey::new(&mut rng);
            hldr = sk.as_bytes().as_ptr();
        }
        unsafe {
            assert_eq!(slice::from_raw_parts(hldr, 32), zero_sk);
        }
    }
}
