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

pub mod extended_keys;

use crate::hash::{Blake2b32Stream, StreamHasher};
use crate::random::{CryptoRng, Rng};
use secp256k1;
use serialization::{Decode, Encode};
use zeroize::Zeroize;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum Secp256k1KeyError {
    InvalidData,
}

#[derive(Debug, PartialEq, Eq, Clone)]
// TODO(SECURITY) erase secret on drop
pub struct Secp256k1PrivateKey {
    data: secp256k1::SecretKey,
}

impl Encode for Secp256k1PrivateKey {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.data.as_ref().using_encoded(f)
    }
}

impl Decode for Secp256k1PrivateKey {
    fn decode<I: serialization::Input>(input: &mut I) -> Result<Self, serialization::Error> {
        let mut v = <[u8; secp256k1::constants::SECRET_KEY_SIZE]>::decode(input)?;
        let result = secp256k1::SecretKey::from_slice(&v)
            .map(|r| Secp256k1PrivateKey { data: r })
            .map_err(|_| serialization::Error::from("Private Key deserialization failed"));
        v.zeroize();
        result
    }
}

impl From<secp256k1::SecretKey> for Secp256k1PrivateKey {
    fn from(sk: secp256k1::SecretKey) -> Self {
        Self { data: sk }
    }
}

impl Secp256k1PrivateKey {
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> (Secp256k1PrivateKey, Secp256k1PublicKey) {
        let secret = secp256k1::SecretKey::new(rng);
        let public = secret.public_key(secp256k1::SECP256K1);
        (
            Secp256k1PrivateKey::from_native(secret),
            Secp256k1PublicKey::from_native(public),
        )
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.data.as_ref()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Secp256k1KeyError> {
        secp256k1::SecretKey::from_slice(bytes)
            .map(|r| Secp256k1PrivateKey { data: r })
            .map_err(|_| Secp256k1KeyError::InvalidData)
    }

    pub fn as_native(&self) -> &secp256k1::SecretKey {
        &self.data
    }

    pub fn from_native(native: secp256k1::SecretKey) -> Self {
        Self { data: native }
    }

    pub(crate) fn sign_message(&self, msg: &[u8]) -> secp256k1::schnorr::Signature {
        let secp = secp256k1::Secp256k1::new();
        // Hash the message
        let e = Blake2b32Stream::new().write(msg).finalize();
        let msg_hash = secp256k1::Message::from_slice(e.as_slice()).expect("Blake2b32 is 32 bytes");
        // Sign the hash
        // TODO(SECURITY) erase keypair after signing
        let keypair = self.data.keypair(&secp);
        // TODO(SECURITY) examine the usage of sign_schnorr_with_rng or a RFC6979 scheme
        secp.sign_schnorr(&msg_hash, &keypair)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Secp256k1PublicKey {
    pubkey_data: secp256k1::PublicKey,
}

impl Encode for Secp256k1PublicKey {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.as_bytes().using_encoded(f)
    }
}

impl Decode for Secp256k1PublicKey {
    fn decode<I: serialization::Input>(input: &mut I) -> Result<Self, serialization::Error> {
        let v = <[u8; secp256k1::constants::PUBLIC_KEY_SIZE]>::decode(input)?;
        secp256k1::PublicKey::from_slice(&v)
            .map(|r| Secp256k1PublicKey { pubkey_data: r })
            .map_err(|_| serialization::Error::from("Public Key deserialization failed"))
    }
}

impl From<secp256k1::PublicKey> for Secp256k1PublicKey {
    fn from(pk: secp256k1::PublicKey) -> Self {
        Self { pubkey_data: pk }
    }
}

impl Secp256k1PublicKey {
    pub fn as_bytes(&self) -> [u8; secp256k1::constants::PUBLIC_KEY_SIZE] {
        self.pubkey_data.serialize()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Secp256k1KeyError> {
        secp256k1::PublicKey::from_slice(bytes)
            .map(|r| Secp256k1PublicKey { pubkey_data: r })
            .map_err(|_| Secp256k1KeyError::InvalidData)
    }

    pub fn as_native(&self) -> &secp256k1::PublicKey {
        &self.pubkey_data
    }

    pub fn from_native(native: secp256k1::PublicKey) -> Self {
        Self {
            pubkey_data: native,
        }
    }

    pub fn from_private_key(private_key: &Secp256k1PrivateKey) -> Self {
        Self::from_native(private_key.data.public_key(secp256k1::SECP256K1))
    }

    pub(crate) fn verify_message(
        &self,
        signature: &secp256k1::schnorr::Signature,
        msg: &[u8],
    ) -> bool {
        // Hash the message
        let e = Blake2b32Stream::new().write(msg).finalize();
        let msg_hashed =
            secp256k1::Message::from_slice(e.as_slice()).expect("Blake2b32 is 32 bytes");
        // Verify the signature
        self.verify_message_hashed(signature, &msg_hashed)
    }

    pub(crate) fn verify_message_hashed(
        &self,
        signature: &secp256k1::schnorr::Signature,
        msg_hashed: &secp256k1::Message,
    ) -> bool {
        secp256k1::SECP256K1
            .verify_schnorr(
                signature,
                msg_hashed,
                &self.pubkey_data.x_only_public_key().0,
            )
            .is_ok()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::random::make_true_rng;
    use hex::ToHex;
    use secp256k1::SECP256K1;
    use serialization::DecodeAll;
    use serialization::Encode;

    #[test]
    fn basic() {
        let mut rng = make_true_rng();
        let (sk, pk) = Secp256k1PrivateKey::new(&mut rng);
        let pk2 = Secp256k1PublicKey::from_private_key(&sk);
        assert_eq!(pk, pk2);
    }

    #[test]
    fn import_from_short_key() {
        let mut rng = make_true_rng();
        let (sk, pk) = Secp256k1PrivateKey::new(&mut rng);
        {
            let sk_bytes = sk.as_bytes();
            let sk_short = &sk_bytes[..sk_bytes.len() - 1];
            assert_eq!(sk_short.len(), 31);
            let sk_again = Secp256k1PrivateKey::from_bytes(sk_short);
            assert!(sk_again.is_err());
        }
        {
            let pk_bytes = pk.as_bytes();
            let pk_short = &pk_bytes[..pk_bytes.len() - 1];
            assert_eq!(pk_short.len(), 32);
            let pk_again = Secp256k1PublicKey::from_bytes(pk_short);
            assert!(pk_again.is_err());
        }
    }

    #[test]
    fn serialize() {
        let mut rng = make_true_rng();
        let (sk, pk) = Secp256k1PrivateKey::new(&mut rng);
        let sk_encoded = sk.encode();
        let pk_encoded = pk.encode();
        let sk2 = Secp256k1PrivateKey::decode_all(&mut sk_encoded.as_slice()).unwrap();
        let pk2 = Secp256k1PublicKey::decode_all(&mut pk_encoded.as_slice()).unwrap();
        assert_eq!(sk, sk2);
        assert_eq!(pk, pk2);
    }

    #[test]
    fn serialize_chosen_data() {
        let sk_pk_hex = vec![
            (
                "0000000000000000000000000000000000000000000000000000000000000003",
                "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            ),
            (
                "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef",
                "02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            ),
            (
                "c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9",
                "02dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
            ),
            (
                "0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710",
                "0325d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517",
            ),
        ];

        for (sk_hex, pk_hex) in sk_pk_hex {
            let sk = Secp256k1PrivateKey::from_bytes(&hex::decode(sk_hex).unwrap()).unwrap();
            let pk = Secp256k1PublicKey::from_bytes(&hex::decode(pk_hex).unwrap()).unwrap();

            assert_eq!(pk.as_native(), &sk.as_native().public_key(SECP256K1));

            let sk_encoded = sk.encode();
            let pk_encoded = pk.encode();

            assert_eq!(sk_encoded.encode_hex::<String>(), sk_hex);
            assert_eq!(pk_encoded.encode_hex::<String>(), pk_hex);

            let sk2 = Secp256k1PrivateKey::decode_all(&mut sk_encoded.as_slice()).unwrap();
            let pk2 = Secp256k1PublicKey::decode_all(&mut pk_encoded.as_slice()).unwrap();

            assert_eq!(sk, sk2);
            assert_eq!(pk, pk2);
        }
    }

    #[test]
    fn invalid_public_keys() {
        let pk_hex = vec![
            "eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34",
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
        ];

        for pk_hex in pk_hex {
            let res = Secp256k1PublicKey::from_bytes(&hex::decode(pk_hex).unwrap()).unwrap_err();
            assert_eq!(res, Secp256k1KeyError::InvalidData);
        }
    }

    #[test]
    fn sign_and_verify() {
        let mut rng = make_true_rng();
        let msg_size = 1 + rand::random::<usize>() % 10000;
        let msg: Vec<u8> = (0..msg_size).map(|_| rand::random::<u8>()).collect();
        let (sk, pk) = Secp256k1PrivateKey::new(&mut rng);
        let sig = sk.sign_message(&msg);
        assert!(pk.verify_message(&sig, &msg));
    }

    #[test]
    fn sign_empty() {
        let mut rng = make_true_rng();
        let msg: Vec<u8> = Vec::new();
        let (sk, pk) = Secp256k1PrivateKey::new(&mut rng);
        let sig = sk.sign_message(&msg);
        assert!(pk.verify_message(&sig, &msg));
    }

    #[test]
    #[ignore]
    fn sk_zeroed() {
        let mut rng = make_true_rng();
        let (mut sk, _) = Secp256k1PrivateKey::new(&mut rng);
        unsafe { core::ptr::drop_in_place(&mut sk) };
        let zero_sk = &vec![0u8; secp256k1::constants::SECRET_KEY_SIZE];
        assert_eq!(sk.as_bytes(), zero_sk);
    }

    #[test]
    fn signature_verification() {
        let test_vec = vec![
            ("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", "0000000000000000000000000000000000000000000000000000000000000000", "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0", true),
            ("02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a", true),
            ("02dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8", "7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c", "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7", true),
            ("0325d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3", true),
            ("02d69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9", "4df3c3f68fcc83b27e9d42c90431a72499f17875c81a599b566c9889b9696703", "00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6376afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4", true),
            ("02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975563cc27944640ac607cd107ae10923d9ef7a73c643e166be5ebeafa34b1ac553e2", false),
            ("02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "1fa62e331edbc21c394792d2ab1100a7b432b013df3f6ff4f99fcb33e0e1515f28890b3edb6e7189b630448b515ce4f8622a954cfe545735aaea5134fccdb2bd", false),
            ("02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769961764b3aa9b2ffcb6ef947b6887a226e8d7c93e00c5ed0c1834ff0d0c2e6da6", false),
            ("02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "0000000000000000000000000000000000000000000000000000000000000000123dda8328af9c23a94c1feecfd123ba4fb73476f0d594dcb65c6425bd186051", false),
            ("02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "00000000000000000000000000000000000000000000000000000000000000017615fbaf5ae28864013c099742deadb4dba87f11ac6754f93780d5a1837cf197", false),
            ("02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "4a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b", false),
            ("02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b", false),
            ("02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", false),
        ];

        for (pk, msg_hash, sig, is_valid) in test_vec {
            let pk = Secp256k1PublicKey::from_bytes(&hex::decode(pk).unwrap()).unwrap();
            let sig =
                secp256k1::schnorr::Signature::from_slice(&hex::decode(sig).unwrap()).unwrap();
            let msg_hash = secp256k1::Message::from_slice(&hex::decode(msg_hash).unwrap()).unwrap();
            assert_eq!(pk.verify_message_hashed(&sig, &msg_hash), is_valid);
        }
    }
}
