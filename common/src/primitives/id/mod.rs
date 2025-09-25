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

// TODO: consider removing this in the future when fixed-hash fixes this problem
#![allow(clippy::non_canonical_clone_impl)]

mod with_id;

use std::fmt::{Debug, Display, LowerHex, UpperHex};

use generic_array::{typenum, GenericArray};
use ref_cast::RefCast;

use crypto::hash::StreamHasher;
use randomness::Rng;
use serialization::{Decode, Encode};
use typename::TypeName;

use crate::Uint256;

pub use with_id::WithId;

fixed_hash::construct_fixed_hash! {
    #[derive(Encode, Decode)]
    pub struct H256(32);
}

impl H256 {
    /// Encoding H256 will result in big-endian encoding of the bytes. Bitcoin uses little-endian for displaying hashes.
    /// This method fills that gap, where we make it possible to print the hash in little-endian to conform to how bitcoin
    /// does it.
    ///
    /// Notice that the internal representation does not really matter in this. What matters is how we view the contents.
    /// If the content is viewed as a number, then serializing the number will result in little-endian encoding because
    /// scale-codec (and bitcoin) use little-endian encoding/serialization by default. On the other hand, if the contents
    /// are viewed as a byte-array (as is the case with H256), then serializing the type will result in whatever that
    /// byte-array is with no regard to endianness, which is done as big-endian in H256 if seen as a number.
    pub fn as_bitcoin_uint256_hex(&self) -> String {
        let hex_length = self.0.len() * 2;
        self.as_bytes()
            .iter()
            .rev()
            .fold(String::with_capacity(hex_length), |mut current, b| {
                use std::fmt::Write;
                let _ = write!(current, "{b:02x}");
                current
            })
    }

    pub fn into_arith_uint256(self) -> Uint256 {
        Uint256::from(self)
    }
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
        impl serde::de::Visitor<'_> for HashVisitor {
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

impl rpc_description::HasValueHint for H256 {
    const HINT_SER: rpc_description::ValueHint = rpc_description::ValueHint::HEX_STRING;
}

#[derive(PartialEq, Eq, Encode, Decode, RefCast)]
#[repr(transparent)]
pub struct Id<T> {
    hash: H256,
    _shadow: std::marker::PhantomData<fn() -> T>,
}

impl<T: TypeName> Debug for Id<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Id<{}>{{{:x}}}", T::typename_str(), self.hash)
    }
}

// Implementing Clone manually to avoid the Clone constraint on T
impl<T> Clone for Id<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Id<T> {}

impl<T> Display for Id<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.hash.to_string();
        write!(
            f,
            "{}",
            self.hash.to_string().strip_prefix("0x").unwrap_or(&s)
        )
    }
}

impl<T> LowerHex for Id<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        for i in &self.hash.0[..] {
            write!(f, "{:02x}", i)?;
        }
        Ok(())
    }
}

impl<T> UpperHex for Id<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "0X")?;
        }
        for i in &self.hash.0[..] {
            write!(f, "{:02X}", i)?;
        }
        Ok(())
    }
}

// We implement Ord manually to avoid it getting inherited to T through PhantomData, because Id having Ord doesn't mean T requiring Ord
impl<T: Eq> Ord for Id<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.hash.cmp(&other.hash)
    }
}

// We implement PartialOrd manually to avoid it getting inherited to T through PhantomData, because Id having PartialOrd doesn't mean T requiring Ord
impl<T: Eq> PartialOrd for Id<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Eq> From<H256> for Id<T> {
    fn from(hash: H256) -> Self {
        Self::new(hash)
    }
}

impl<T> Id<T> {
    pub const fn to_hash(&self) -> H256 {
        self.hash
    }

    pub const fn as_hash(&self) -> &H256 {
        &self.hash
    }

    pub const fn new(h: H256) -> Self {
        Self {
            hash: h,
            _shadow: std::marker::PhantomData,
        }
    }

    pub const fn zero() -> Self {
        Self::new(H256::zero())
    }

    pub fn random_using<R: Rng>(rng: &mut R) -> Self {
        Self::new(H256::random_using(rng))
    }

    pub fn serde_serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        <H256 as serde::Serialize>::serialize(&self.hash, s)
    }

    pub fn serde_deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        <H256 as serde::Deserialize<'de>>::deserialize(d).map(Self::new)
    }
}

impl serde::Serialize for Id<()> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.serde_serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for Id<()> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::serde_deserialize(d)
    }
}

impl<T> AsRef<[u8]> for Id<T> {
    fn as_ref(&self) -> &[u8] {
        &self.hash[..]
    }
}

impl<T> rpc_description::HasValueHint for Id<T> {
    const HINT_SER: rpc_description::ValueHint = rpc_description::ValueHint::HEX_STRING;
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

/// Implementing this trait for some type `T` means that:
/// 1) `T` has a sub-object of type `SubObj`.
/// 2) Id of `SubObj` is the same as id of `T`.
///
/// Example: `Block` contains `SignedHeader` and the block id is the same as its header's.
pub trait HasSubObjWithSameId<SubObj>: Idable
where
    SubObj: Idable<Tag = <Self as Idable>::Tag>,
{
    fn get_sub_obj(&self) -> &SubObj;
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

    #[test]
    fn basic_str() {
        let h1: Id<TestType1> =
            H256::from_str("000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd")
                .unwrap()
                .into();

        assert_eq!(
            format!("{:x}", h1),
            "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd".to_string()
        );
        assert_eq!(
            format!("{:#x}", h1),
            "0x000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd".to_string()
        );
        assert_eq!(
            format!("{:X}", h1),
            "000000006A625F06636B8BB6AC7B960A8D03705D1ACE08B1A19DA3FDCC99DDBD".to_string()
        );
        assert_eq!(
            format!("{:#X}", h1),
            "0X000000006A625F06636B8BB6AC7B960A8D03705D1ACE08B1A19DA3FDCC99DDBD".to_string()
        );
        assert_eq!(format!("{}", h1), "0000…ddbd".to_string());
        assert_eq!(
            format!("{:?}", h1),
            "Id<TestType1>{000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd}"
                .to_string()
        );
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
        use randomness::{make_pseudo_rng, Rng};
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

            let hash_str = "0x".to_string() + &hash_value.as_bitcoin_uint256_hex();
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
            let bytes: Vec<u8> = FromHex::from_hex(hex).unwrap();
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
                Some(Value::String(format!("{:x}", id.hash)))
            );
        }
        SAMPLE_HASHES.iter().cloned().for_each(check)
    }

    #[test]
    fn display_test() {
        fn check(hash: &str) {
            let h256 = H256::from_str(hash).expect("should not fail");

            let debug = format!("{h256:?}");
            assert_eq!(debug, format!("0x{hash}"));

            let display = format!("{h256}");
            let (_, last_value) = hash.split_at(hash.len() - 4);
            assert_eq!(display, format!("0x{}…{}", &hash[0..4], last_value));

            let no_0x = format!("{h256:x}");
            assert_eq!(no_0x, hash.to_string());

            let sharp = format!("{h256:#x}");
            assert_eq!(sharp, debug);

            let upper_hex = format!("{h256:#010X}");
            assert_eq!(upper_hex, format!("0X{}", hash.to_uppercase()));
        }

        check("000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c");
        check("000000000000000004ec466ce4732fe6f1ed1cddc2ed4b328fff5224276e3f6f");
        check("000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd");
    }
}
