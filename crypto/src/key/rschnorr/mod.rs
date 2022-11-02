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

use crate::key::hdkd::derivation_path::ChildNumber;
use crate::key::hdkd::DerivationError::UnsupportedDerivationType;
use crate::key::hdkd::{Derivable, DerivationError};
use crate::random::{CryptoRng, Rng};
use schnorrkel::derive::{ChainCode, CHAIN_CODE_LENGTH};
use schnorrkel::ExpansionMode::Ed25519;
use serialization::{Decode, Encode};
use zeroize::Zeroize;

const SIGNATURE_CONTEXT: &[u8; 19] = b"mintlayer-signature";

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
    key_data: schnorrkel::SecretKey,
}

impl Encode for MLRistrettoPrivateKey {
    fn encode(&self) -> Vec<u8> {
        let mut key_bytes = self.key_data.to_ed25519_bytes();
        let encoded = key_bytes.as_ref().encode();
        key_bytes.zeroize();
        encoded
    }

    fn encoded_size(&self) -> usize {
        let mut key_bytes = self.key_data.to_ed25519_bytes();
        let size = key_bytes.as_ref().encoded_size();
        key_bytes.zeroize();
        size
    }

    fn encode_to<T: serialization::Output + ?Sized>(&self, dest: &mut T) {
        let mut key_bytes = self.key_data.to_ed25519_bytes();
        key_bytes.as_ref().encode_to(dest);
        key_bytes.zeroize();
    }

    fn size_hint(&self) -> usize {
        let mut key_bytes = self.key_data.to_ed25519_bytes();
        let size_hint = key_bytes.as_ref().size_hint();
        key_bytes.zeroize();
        size_hint
    }

    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        let mut key_bytes = self.key_data.to_ed25519_bytes();
        let using_encoded = key_bytes.as_ref().using_encoded(f);
        key_bytes.zeroize();
        using_encoded
    }
}

impl Decode for MLRistrettoPrivateKey {
    fn decode<I: serialization::Input>(input: &mut I) -> Result<Self, serialization::Error> {
        let mut v = Vec::decode(input)?;
        let result = schnorrkel::SecretKey::from_ed25519_bytes(&v)
            .map(|r| MLRistrettoPrivateKey { key_data: r })
            .map_err(|_| serialization::Error::from("Private Key deserialization failed"));
        v.zeroize();
        result
    }
}

impl MLRistrettoPrivateKey {
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> (MLRistrettoPrivateKey, MLRistrettoPublicKey) {
        let secret = schnorrkel::SecretKey::generate_with(rng);
        let public = secret.to_public();
        (
            MLRistrettoPrivateKey::from_native(secret),
            MLRistrettoPublicKey::from_native(public),
        )
    }

    pub fn as_bytes(&self) -> [u8; schnorrkel::SECRET_KEY_LENGTH] {
        /*
        TODO consider removing this method as it copies secret data to an array that is
        not automatically zeroed after use. If this is needed then consider returning
        secrecy::Secret<[u8; schnorrkel::SECRET_KEY_LENGTH]>
        */
        self.key_data.to_ed25519_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RistrettoKeyError> {
        let sk = schnorrkel::SecretKey::from_ed25519_bytes(bytes)
            .map_err(|_| RistrettoKeyError::InvalidData)?;
        let result = Self::from_native(sk);
        Ok(result)
    }

    pub fn as_native(&self) -> &schnorrkel::SecretKey {
        &self.key_data
    }

    pub fn from_native(native: schnorrkel::SecretKey) -> Self {
        Self { key_data: native }
    }

    pub(crate) fn sign_message(
        &self,
        msg: &[u8],
    ) -> Result<schnorrkel::Signature, RistrettoSignatureError> {
        let ctx = schnorrkel::signing_context(SIGNATURE_CONTEXT);
        let pub_key = self.key_data.to_public();
        let transcript = ctx.bytes(msg);
        let sig = self.key_data.sign(transcript, &pub_key);
        Ok(sig)
    }

    fn child_num_to_chaincode(num: ChildNumber) -> ChainCode {
        let mut chaincode = ChainCode([0u8; CHAIN_CODE_LENGTH]);
        chaincode.0[0..4].copy_from_slice(&num.to_encoded_index().to_be_bytes());
        chaincode
    }
}

impl Derivable for MLRistrettoPrivateKey {
    fn derive_child(self, num: ChildNumber) -> Result<Self, DerivationError> {
        // We can perform only hard derivations
        if !num.is_hardened() {
            return Err(UnsupportedDerivationType);
        }
        let chaincode = Some(MLRistrettoPrivateKey::child_num_to_chaincode(num));
        let mini_key = self.as_native().hard_derive_mini_secret_key(chaincode, b"").0;
        let key = MLRistrettoPrivateKey::from_native(mini_key.expand(Ed25519));
        Ok(key)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct MLRistrettoPublicKey {
    pubkey_data: schnorrkel::PublicKey,
}

impl Encode for MLRistrettoPublicKey {
    fn encode(&self) -> Vec<u8> {
        self.pubkey_data.as_ref().encode()
    }

    fn encoded_size(&self) -> usize {
        self.pubkey_data.as_ref().encoded_size()
    }

    fn encode_to<T: serialization::Output + ?Sized>(&self, dest: &mut T) {
        self.pubkey_data.as_ref().encode_to(dest)
    }

    fn size_hint(&self) -> usize {
        self.pubkey_data.as_ref().size_hint()
    }

    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.pubkey_data.as_ref().using_encoded(f)
    }
}

impl Decode for MLRistrettoPublicKey {
    fn decode<I: serialization::Input>(input: &mut I) -> Result<Self, serialization::Error> {
        let v = Vec::decode(input)?;
        schnorrkel::PublicKey::from_bytes(&v)
            .map(|r| MLRistrettoPublicKey { pubkey_data: r })
            .map_err(|_| serialization::Error::from("Public Key deserialization failed"))
    }
}

impl MLRistrettoPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        self.pubkey_data.as_ref()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RistrettoKeyError> {
        let pk =
            schnorrkel::PublicKey::from_bytes(bytes).map_err(|_| RistrettoKeyError::InvalidData)?;
        let result = Self::from_native(pk);
        Ok(result)
    }

    pub fn as_native(&self) -> &schnorrkel::PublicKey {
        &self.pubkey_data
    }

    pub fn from_native(native: schnorrkel::PublicKey) -> Self {
        Self {
            pubkey_data: native,
        }
    }

    pub fn from_private_key(private_key: &MLRistrettoPrivateKey) -> Self {
        Self::from_native(private_key.key_data.to_public())
    }

    pub(crate) fn verify_message(&self, signature: &schnorrkel::Signature, msg: &[u8]) -> bool {
        let ctx = schnorrkel::signing_context(SIGNATURE_CONTEXT);
        self.pubkey_data.verify(ctx.bytes(msg), signature).is_ok()
    }
}

impl std::ops::Add for &MLRistrettoPublicKey {
    type Output = MLRistrettoPublicKey;
    fn add(self, rhs: Self) -> MLRistrettoPublicKey {
        let result = self.pubkey_data.as_point() + rhs.pubkey_data.as_point();
        MLRistrettoPublicKey::from_native(schnorrkel::PublicKey::from_point(result))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::key::hdkd::derivation_path::DerivationPath;
    use crate::random::make_true_rng;
    use hex::ToHex;
    use serialization::DecodeAll;
    use serialization::{Decode, Encode};
    use std::str::FromStr;

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
            assert_eq!(sk_short.len(), 63);
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
        let sk = MLRistrettoPrivateKey::from_bytes(
            &hex::decode("181b259bac04d8ec3f6ea2a86b37f39a353288a8410fc469b9f2d5c59ce30a36c10bfdc906c8343fe0fb42c2564d6b1d3bf8ae3d73f0f7e5424cb60a9639d7e0")
                .unwrap(),
        )
        .unwrap();
        let pk = MLRistrettoPublicKey::from_bytes(
            &hex::decode("283462ee4f0840e21d6de7744ba42929d1b74b7a948e8229d9551e7760ec8c52")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(pk.as_native(), &sk.as_native().to_public());

        let sk_encoded = sk.encode();
        let pk_encoded = pk.encode();

        assert_eq!(sk_encoded.encode_hex::<String>(), "0101181b259bac04d8ec3f6ea2a86b37f39a353288a8410fc469b9f2d5c59ce30a36c10bfdc906c8343fe0fb42c2564d6b1d3bf8ae3d73f0f7e5424cb60a9639d7e0");
        assert_eq!(
            pk_encoded.encode_hex::<String>(),
            "80283462ee4f0840e21d6de7744ba42929d1b74b7a948e8229d9551e7760ec8c52"
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
        let sig = sk.sign_message(&msg).unwrap();
        assert!(pk.verify_message(&sig, &msg));
    }

    #[test]
    fn sign_empty() {
        let mut rng = make_true_rng();
        let msg: Vec<u8> = Vec::new();
        let (sk, pk) = MLRistrettoPrivateKey::new(&mut rng);
        let sig = sk.sign_message(&msg).unwrap();
        assert!(pk.verify_message(&sig, &msg));
    }

    #[test]
    fn sk_zeroed() {
        let mut rng = make_true_rng();
        let (mut sk, _) = MLRistrettoPrivateKey::new(&mut rng);
        unsafe { core::ptr::drop_in_place(&mut sk) };
        let zero_sk = &vec![0u8; 64];
        assert_eq!(sk.as_bytes().as_ref(), zero_sk);
    }

    #[test]
    fn add_public_keys() {
        let pk1 = "d819669a3c9f79aee57e2ae6be47f78444feda3796fdf72ca1f428a2edecc909";
        let pk2 = "ce3138c10e1858ac26f342c7cad4a974975af93835d59004a91508ea472a8375";
        let pk_sum = "64dc721dcf6b7a9cc75db624681cc33d6d8e4080b7bc371da9ca1dfbeb497d21";

        let pk1 = MLRistrettoPublicKey::from_bytes(&hex::decode(pk1).unwrap()).unwrap();
        let pk2 = MLRistrettoPublicKey::from_bytes(&hex::decode(pk2).unwrap()).unwrap();
        let pk_sum = MLRistrettoPublicKey::from_bytes(&hex::decode(pk_sum).unwrap()).unwrap();

        assert_eq!(&pk1 + &pk2, pk_sum);
    }

    #[test]
    fn test_derivation_private_key() {
        let sk_bytes = hex::decode("0101181b259bac04d8ec3f6ea2a86b37f39a353288a8410fc469b9f2d5c59ce30a36c10bfdc906c8343fe0fb42c2564d6b1d3bf8ae3d73f0f7e5424cb60a9639d7e0").unwrap();
        let sk = MLRistrettoPrivateKey::decode(&mut sk_bytes.as_slice()).unwrap();

        let path = DerivationPath::from_str("m/0'").unwrap();
        let child_sk = sk.clone().derive_path(&path).unwrap();

        assert_eq!(hex::encode(child_sk.encode()), "010118959f5bfcde4299d177763c94c30b56cd8a7df22d6fc4861d45067c4dccd0470957e0852e2b4af0d8d44a29ad8fdf17db6cf0f5f7feef9d268790b326bda500");

        let child_sk_final = child_sk.derive_child(ChildNumber::hardened(1).unwrap()).unwrap();

        let path = DerivationPath::from_str("m/0'/1'").unwrap();
        let child_sk_final_alt = sk.derive_path(&path).unwrap();

        assert_eq!(child_sk_final.encode(), child_sk_final_alt.encode());

        assert_eq!(
            hex::encode(child_sk_final.encode()),
            "010110088b095ac8dac54b0a4837031e90731a0c442240a532889295ade79e924a700e7a2e2030eaf4b37a317bd79191535d21be2582422b65fabcc7157109dc4271"
        );
    }
}
