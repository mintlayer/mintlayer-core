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

use crypto::hash::{self, hash};
use randomness::Rng;
use serialization::{Decode, Encode};

use super::{timelock::OutputTimeLock, Destination};

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, serde::Serialize, serde::Deserialize)]
pub struct HashedTimelockContract {
    // can be spent either by a specific address that knows the secret
    pub secret_hash: HtlcSecretHash,
    pub spend_key: Destination,

    // or by a multisig after timelock expires making it possible to refund
    pub refund_timelock: OutputTimeLock,
    pub refund_key: Destination,
}

#[derive(Clone, Encode, Decode, PartialEq, Eq, Debug)]
pub struct HtlcSecret {
    secret: [u8; 32],
}

impl HtlcSecret {
    pub fn new(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    pub fn new_from_rng(rng: &mut impl Rng) -> Self {
        let secret: [u8; 32] = std::array::from_fn(|_| rng.gen::<u8>());
        Self { secret }
    }

    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    pub fn consume(self) -> [u8; 32] {
        self.secret
    }

    pub fn hash(&self) -> HtlcSecretHash {
        HtlcSecretHash::from_slice(
            hash::<hash::Ripemd160, _>(hash::<hash::Sha256, _>(&self.secret)).as_slice(),
        )
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
        impl<'de> serde::de::Visitor<'de> for HashVisitor {
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
    use rstest::rstest;
    use test_utils::random::Seed;

    use super::HtlcSecretHash;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn serialize_roundtrip(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let hash = HtlcSecretHash::random_using(&mut rng);
        let s_json = serde_json::to_string(&hash).unwrap();
        let decoded = serde_json::from_str::<HtlcSecretHash>(&s_json).unwrap();

        assert_eq!(hash, decoded);
    }

    #[rstest]
    #[case("\"0000000000000000000000000000000000000000\"", [0;20])]
    #[case("\"0000000000000000000000000000000000000001\"", [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1])]
    #[case("\"ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd\"", [0xac,0x7b,0x96,0x0a,0x8d,0x03,0x70,0x5d,0x1a,0xce,0x08,0xb1,0xa1,0x9d,0xa3,0xfd,0xcc,0x99,0xdd,0xbd])]
    #[case("\"e4732fe6f1ed1cddc2ed4b328fff5224276e3f6f\"", [0xe4,0x73,0x2f,0xe6,0xf1,0xed,0x1c,0xdd,0xc2,0xed,0x4b,0x32,0x8f,0xff,0x52,0x24,0x27,0x6e,0x3f,0x6f])]
    #[case("\"0103b9683e51e5aba83b8a34c9b98ce67d66136c\"", [0x01,0x03,0xb9,0x68,0x3e,0x51,0xe5,0xab,0xa8,0x3b,0x8a,0x34,0xc9,0xb9,0x8c,0xe6,0x7d,0x66,0x13,0x6c])]
    fn deserialize_valid(#[case] str: String, #[case] expected: [u8; 20]) {
        let result = serde_json::from_str::<HtlcSecretHash>(&str).unwrap();
        assert_eq!(result, HtlcSecretHash::from_slice(&expected));
    }

    #[rstest]
    #[case(
        "\"00000000000000000000000000000000000000000000000000000000000000\"",
        "Invalid input length"
    )]
    #[case("\"000000000000000000000000000000000invalid\"", "Invalid character")]
    fn deserialize_invalid(#[case] s: String, #[case] expected_msg: String) {
        let err = serde_json::from_str::<HtlcSecretHash>(&s).unwrap_err();
        assert!(err.to_string().contains(&expected_msg));
    }
}
