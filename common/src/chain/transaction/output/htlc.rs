// Copyright (c) 2024 RBB S.r.l
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

// TODO: consider removing this in the future when fixed-hash fixes this problem
#![allow(clippy::non_canonical_clone_impl)]

use hex::FromHex as _;

use crypto::hash::{self, hash};
use randomness::{CryptoRng, Rng};
use serialization::{Decode, Encode};

use super::{timelock::OutputTimeLock, Destination};

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, serde::Serialize, serde::Deserialize)]
pub struct HashedTimelockContract {
    /// Can be spent either via `spend_key` by someone who knows the secret.
    pub secret_hash: HtlcSecretHash,
    pub spend_key: Destination,

    /// Or via `refund_key` after the timelock expires.
    pub refund_timelock: OutputTimeLock,
    pub refund_key: Destination,
}

pub const HTLC_SECRET_SIZE: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct HtlcSecret {
    secret: [u8; HTLC_SECRET_SIZE],
}

impl HtlcSecret {
    pub fn new(secret: [u8; HTLC_SECRET_SIZE]) -> Self {
        Self { secret }
    }

    pub fn new_from_rng(rng: &mut (impl Rng + CryptoRng)) -> Self {
        let secret: [u8; HTLC_SECRET_SIZE] = std::array::from_fn(|_| rng.gen::<u8>());
        Self { secret }
    }

    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    pub fn consume(self) -> [u8; HTLC_SECRET_SIZE] {
        self.secret
    }

    pub fn hash(&self) -> HtlcSecretHash {
        HtlcSecretHash::from_slice(
            hash::<hash::Ripemd160, _>(hash::<hash::Sha256, _>(&self.secret)).as_slice(),
        )
    }
}

impl rpc_description::HasValueHint for HtlcSecret {
    const HINT_SER: rpc_description::ValueHint = rpc_description::ValueHint::Array(&u8::HINT_SER);
}

impl serde::Serialize for HtlcSecret {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(&self.secret[..]))
    }
}

impl<'de> serde::Deserialize<'de> for HtlcSecret {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = HtlcSecret;
            fn expecting(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                fmt.write_str("a hex-encoded secret")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                let secret = <_>::from_hex(s).map_err(serde::de::Error::custom)?;
                Ok(HtlcSecret { secret })
            }
        }
        d.deserialize_str(Visitor)
    }
}

fixed_hash::construct_fixed_hash! {
    #[derive(Encode, Decode)]
    pub struct HtlcSecretHash(20);
}

impl rpc_description::HasValueHint for HtlcSecretHash {
    const HINT_SER: rpc_description::ValueHint = rpc_description::ValueHint::HEX_STRING;
}

impl serde::Serialize for HtlcSecretHash {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{self:x}"))
    }
}

impl<'de> serde::Deserialize<'de> for HtlcSecretHash {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct HashVisitor;
        impl serde::de::Visitor<'_> for HashVisitor {
            type Value = HtlcSecretHash;
            fn expecting(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                fmt.write_str("a hex-encoded hash")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                s.parse().map_err(serde::de::Error::custom)
            }
        }
        d.deserialize_str(HashVisitor)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rstest::rstest;

    use test_utils::random::Seed;

    use super::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn secret_serialization_roundtrip(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let secret = HtlcSecret::new_from_rng(&mut rng);
        let serialized = serde_json::to_string(&secret).unwrap();
        let deserialized = serde_json::from_str::<HtlcSecret>(&serialized).unwrap();

        assert_eq!(deserialized, secret);
    }

    #[rstest]
    #[case("0000000000000000000000000000000000000000000000000000000000000000", [0;32])]
    #[case(
        "0000000000000000000000000000000000000000000000000000000000000001",
        [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]
    )]
    #[case(
        "b61d725e3454919ea5c52158146bbe378132d48564ce12da5045e352380c355d",
        [
            0xb6,0x1d,0x72,0x5e,0x34,0x54,0x91,0x9e,0xa5,0xc5,0x21,0x58,0x14,0x6b,0xbe,0x37,
            0x81,0x32,0xd4,0x85,0x64,0xce,0x12,0xda,0x50,0x45,0xe3,0x52,0x38,0x0c,0x35,0x5d
        ]
    )]
    #[case(
        "3e192c84a18d49d7100494efb32fd36e52418c192de99b74e2dc06a837f293cb",
        [
            0x3e,0x19,0x2c,0x84,0xa1,0x8d,0x49,0xd7,0x10,0x04,0x94,0xef,0xb3,0x2f,0xd3,0x6e,
            0x52,0x41,0x8c,0x19,0x2d,0xe9,0x9b,0x74,0xe2,0xdc,0x06,0xa8,0x37,0xf2,0x93,0xcb
        ]
    )]
    #[case(
        "1da5d09882ab9db367b8ee481676c9c16d49c48c8f8f94f3e275ad582c764c74",
        [
            0x1d,0xa5,0xd0,0x98,0x82,0xab,0x9d,0xb3,0x67,0xb8,0xee,0x48,0x16,0x76,0xc9,0xc1,
            0x6d,0x49,0xc4,0x8c,0x8f,0x8f,0x94,0xf3,0xe2,0x75,0xad,0x58,0x2c,0x76,0x4c,0x74
        ]
    )]
    fn secret_serialize(#[case] secret_str: &str, #[case] secret_bytes: [u8; HTLC_SECRET_SIZE]) {
        let secret = HtlcSecret::new(secret_bytes);
        let secret_json_str = secret_str_to_json(secret_str);

        let actual_secret_json_str = serde_json::to_string(&secret).unwrap();
        assert_eq!(actual_secret_json_str, secret_json_str);

        let actual_deserialized_secret =
            serde_json::from_str::<HtlcSecret>(&secret_json_str).unwrap();
        assert_eq!(actual_deserialized_secret, secret);
    }

    #[rstest]
    #[case(
        "00000000000000000000000000000000000000000000000000000000000000",
        "Invalid string length"
    )]
    #[case(
        "000000000000000000000000000000000000000000000000000000000invalid",
        "Invalid character"
    )]
    fn secret_deserialize_invalid(#[case] secret_str: &str, #[case] expected_msg: &str) {
        let secret_json_str = secret_str_to_json(secret_str);

        let err = serde_json::from_str::<HtlcSecret>(&secret_json_str).unwrap_err();
        assert!(err.to_string().contains(expected_msg));
    }

    fn secret_str_to_json(secret_str: &str) -> String {
        format!(r#""{secret_str}""#)
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn secret_hash_serialization_roundtrip(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let hash = HtlcSecretHash::random_using(&mut rng);
        let serialized = serde_json::to_string(&hash).unwrap();
        let deserialized = serde_json::from_str::<HtlcSecretHash>(&serialized).unwrap();

        assert_eq!(deserialized, hash);
    }

    #[rstest]
    #[case("0000000000000000000000000000000000000000", [0;20])]
    #[case("0000000000000000000000000000000000000001", [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1])]
    #[case(
        "ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd",
        [0xac,0x7b,0x96,0x0a,0x8d,0x03,0x70,0x5d,0x1a,0xce,0x08,0xb1,0xa1,0x9d,0xa3,0xfd,0xcc,0x99,0xdd,0xbd]
    )]
    #[case(
        "e4732fe6f1ed1cddc2ed4b328fff5224276e3f6f",
        [0xe4,0x73,0x2f,0xe6,0xf1,0xed,0x1c,0xdd,0xc2,0xed,0x4b,0x32,0x8f,0xff,0x52,0x24,0x27,0x6e,0x3f,0x6f]
    )]
    #[case(
        "0103b9683e51e5aba83b8a34c9b98ce67d66136c",
        [0x01,0x03,0xb9,0x68,0x3e,0x51,0xe5,0xab,0xa8,0x3b,0x8a,0x34,0xc9,0xb9,0x8c,0xe6,0x7d,0x66,0x13,0x6c]
    )]
    fn secret_hash_serialize(#[case] hash_str: &str, #[case] hash_bytes: [u8; 20]) {
        let hash = HtlcSecretHash::from_slice(&hash_bytes);
        let hash_json_str = secret_hash_str_to_json(hash_str);

        let actual_hash_json_str = serde_json::to_string(&hash).unwrap();
        assert_eq!(actual_hash_json_str, hash_json_str);

        let actual_deserialized_hash =
            serde_json::from_str::<HtlcSecretHash>(&hash_json_str).unwrap();
        assert_eq!(actual_deserialized_hash, hash);

        let actual_deserialized_hash = hash_str.parse::<HtlcSecretHash>().unwrap();
        assert_eq!(actual_deserialized_hash, hash);

        let actual_deserialized_hash = HtlcSecretHash::from_str(hash_str).unwrap();
        assert_eq!(actual_deserialized_hash, hash);
    }

    #[rstest]
    #[case(
        "00000000000000000000000000000000000000000000000000000000000000",
        "Invalid input length"
    )]
    #[case("000000000000000000000000000000000invalid", "Invalid character")]
    fn secret_hash_deserialize_invalid(#[case] hash_str: &str, #[case] expected_msg: &str) {
        let err = HtlcSecretHash::from_str(hash_str).unwrap_err();
        assert!(err.to_string().contains(expected_msg));

        let hash_json_str = secret_hash_str_to_json(hash_str);
        let err = serde_json::from_str::<HtlcSecretHash>(&hash_json_str).unwrap_err();
        assert!(err.to_string().contains(expected_msg));
    }

    fn secret_hash_str_to_json(hash_str: &str) -> String {
        format!(r#""{hash_str}""#)
    }
}
