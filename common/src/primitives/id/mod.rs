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

mod with_id;

pub use with_id::WithId;

use std::fmt::{Debug, Display};

use crate::{construct_fixed_hash, Uint256};
use generic_array::{typenum, GenericArray};
use serialization::{Decode, Encode};
use typename::TypeName;

construct_fixed_hash! {
    #[derive(Encode, Decode)]
    pub struct H256(32);
}

impl From<GenericArray<u8, typenum::U32>> for H256 {
    fn from(val: GenericArray<u8, typenum::U32>) -> Self {
        Self(val.into())
    }
}

impl From<H256> for Uint256 {
    fn from(hash: H256) -> Self {
        Uint256::from(hash.0)
    }
}

impl From<Uint256> for H256 {
    fn from(val: Uint256) -> Self {
        H256(val.to_bytes())
    }
}

impl serde::Serialize for H256 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{self:x}"))
    }
}

impl<'de> serde::Deserialize<'de> for H256 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct HashVisitor;
        impl<'de> serde::de::Visitor<'de> for HashVisitor {
            type Value = H256;
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

#[derive(PartialEq, Eq, Encode, Decode, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Id<T> {
    id: H256,
    #[serde(skip)]
    _shadow: std::marker::PhantomData<fn() -> T>,
}

impl<T: TypeName> Debug for Id<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Id<{}>{{{:?}}}", T::typename_str(), self.id)
    }
}

// Implementing Clone manually to avoid the Clone constraint on T
impl<T> Clone for Id<T> {
    fn clone(&self) -> Self {
        Self::new(self.id)
    }
}

impl<T> Copy for Id<T> {}

impl<T> Display for Id<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.id, f)
    }
}

// We implement Ord manually to avoid it getting inherited to T through PhantomData, because Id having Ord doesn't mean T requiring Ord
impl<T: Eq> Ord for Id<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

// We implement PartialOrd manually to avoid it getting inherited to T through PhantomData, because Id having PartialOrd doesn't mean T requiring Ord
impl<T: Eq> PartialOrd for Id<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.id.partial_cmp(&other.id)
    }
}

impl<T: Eq> From<H256> for Id<T> {
    fn from(hash: H256) -> Self {
        Self::new(hash)
    }
}

impl<T> Id<T> {
    pub fn get(&self) -> H256 {
        self.id
    }

    pub fn new(h: H256) -> Self {
        Self {
            id: h,
            _shadow: std::marker::PhantomData,
        }
    }
}

impl<T> AsRef<[u8]> for Id<T> {
    fn as_ref(&self) -> &[u8] {
        &self.id[..]
    }
}

/// a trait for objects that deserve having a unique id with implementations to how to ID them
pub trait Idable {
    type Tag: TypeName;
    fn get_id(&self) -> Id<Self::Tag>;
}

impl<T: Idable> Idable for &T {
    type Tag = T::Tag;
    fn get_id(&self) -> Id<Self::Tag> {
        (*self).get_id()
    }
}

// we use a cropping stream (64 => 32) because
// we want a hash result to H256 and a byte array
// of the hash to be identical, while benefiting
// from a strong and software-friendly hash function;
// both the hashing methods below should produce the
// same result
pub type DefaultHashAlgo = crypto::hash::Blake2b32;
pub type DefaultHashAlgoStream = crypto::hash::Blake2b32Stream;

/// Hash given slice using the default hash
pub fn default_hash<T: AsRef<[u8]> + Clone>(data: T) -> H256 {
    crypto::hash::hash::<DefaultHashAlgo, _>(&data).into()
}

/// Feed the encoded version of given value into the default hasher
pub fn hash_encoded_to<T: Encode>(value: &T, hasher: &mut DefaultHashAlgoStream) {
    crate::primitives::hash_encoded::hash_encoded_to(value, hasher)
}

/// Hash the encoded version of given value using the default hash
pub fn hash_encoded<T: Encode>(value: &T) -> H256 {
    use crypto::hash::StreamHasher;
    let mut hasher = DefaultHashAlgoStream::new();
    hash_encoded_to(value, &mut hasher);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::hash::StreamHasher;
    use hex::FromHex;
    use rstest::rstest;
    use std::str::FromStr;
    use test_utils::random::Seed;

    #[derive(Eq, PartialEq, Debug, TypeName)]
    struct TestType1;

    #[derive(Eq, PartialEq, Debug)]
    struct TestType2;

    impl TypeName for TestType2 {
        fn typename_str() -> std::borrow::Cow<'static, str> {
            "TestType2".into()
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn typename(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let h1: Id<TestType1> = H256::random_using(&mut rng).into();
        assert!(format!("{h1:?}").starts_with("Id<TestType1>{"));

        let h2: Id<TestType2> = H256::random_using(&mut rng).into();
        assert!(format!("{h2:?}").starts_with("Id<TestType2>{"));
    }

    #[test]
    fn hashes_stream_and_msg_identical() {
        use crypto::random::{make_pseudo_rng, Rng};
        let random_bytes = make_pseudo_rng().gen::<[u8; H256::len_bytes()]>();

        let h1 = default_hash(random_bytes);
        let mut hash_stream = DefaultHashAlgoStream::new();
        hash_stream.write(random_bytes);
        let h2 = hash_stream.finalize();

        assert_eq!(h1, h2.into());

        let h3 = crypto::hash::hash::<DefaultHashAlgo, _>(random_bytes);

        assert_eq!(h1, h3.into());
    }

    const SAMPLE_HASHES: [&str; 5] = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd",
        "02f0000ff000000004ec466ce4732fe6f1ed1cddc2ed4b328fff5224276e3f6f",
        "000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c",
    ];

    #[test]
    fn h256_to_uint256_and_vice_versa() {
        fn check(value: &str) {
            let hash_value = H256::from_str(value).expect("nothing wrong");
            let uint_value = Uint256::from(hash_value);

            let hash_str = format!("{hash_value:?}");
            let uint_str = format!("{uint_value:?}");
            assert_eq!(hash_str, uint_str);

            // make sure the position of the bytes are the same.
            assert_eq!(hash_value.0, uint_value.to_bytes());
            assert_eq!(hash_value, H256::from(uint_value));
        }

        SAMPLE_HASHES.iter().cloned().for_each(check)
    }

    #[test]
    fn h256_and_uint256_from_bytes_and_bytes_form() {
        fn check(hex: &str) {
            // reverse pairs of bytes as hex
            let hex_reversed =
                String::from_utf8(hex.as_bytes().chunks(2).rev().collect::<Vec<&[u8]>>().concat())
                    .unwrap();

            let bytes: Vec<u8> = FromHex::from_hex(hex_reversed).unwrap();
            let bytes = bytes.as_slice();
            let h = H256::from_str(hex).unwrap();
            let u = Uint256::from_bytes(bytes.try_into().unwrap());
            assert_eq!(h.as_bytes(), bytes);
            assert_eq!(u.to_bytes(), bytes);
        }
        SAMPLE_HASHES.iter().cloned().for_each(check)
    }

    #[test]
    fn h256_json() {
        fn check(hex: &'static str) {
            use serde_json::Value;
            let hash: H256 = hex.parse().unwrap();
            // hash should serialize into its hex string
            serde_test::assert_tokens(&hash, &[serde_test::Token::Str(hex)]);
            assert_eq!(
                serde_json::to_value(hash).ok(),
                Some(Value::String(format!("{hash:x}")))
            );
        }
        SAMPLE_HASHES.iter().cloned().for_each(check)
    }

    #[test]
    fn id_json() {
        fn check(hex: &'static str) {
            use serde_json::Value;
            let id: Id<()> = Id::new(hex.parse().unwrap());
            // ID should serialize into its hex string
            serde_test::assert_tokens(&id, &[serde_test::Token::Str(hex)]);
            assert_eq!(
                serde_json::to_value(id).ok(),
                Some(Value::String(format!("{:x}", id.id)))
            );
        }
        SAMPLE_HASHES.iter().cloned().for_each(check)
    }
}
