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

mod internal;

use generic_array::{sequence::Split, typenum, ArrayLength, GenericArray};
use internal::InternalStreamHasher;

pub trait Hasher {
    type OutputSize: ArrayLength<u8>;

    fn hash<T: AsRef<[u8]>>(data: T) -> GenericArray<u8, Self::OutputSize>;
}

macro_rules! impl_hasher_trait {
    ($stream_type:ident, $internal_digest_type:ty, $stream_size:ty) => {
        pub struct $stream_type;

        impl Hasher for $stream_type {
            type OutputSize = $stream_size;

            fn hash<T: AsRef<[u8]>>(data: T) -> GenericArray<u8, Self::OutputSize> {
                // The split method below chooses the split point based on type,
                // see the docs for [generic_array::sequence::Split] for more info.
                internal::hash::<$internal_digest_type, T>(data).split().0
            }
        }
    };
}

impl_hasher_trait!(Blake2b, blake2::Blake2b<typenum::U64>, typenum::U64);
impl_hasher_trait!(Blake2b32, blake2::Blake2b<typenum::U64>, typenum::U32);
impl_hasher_trait!(Sha1, sha1::Sha1, typenum::U20);
impl_hasher_trait!(Sha256, sha2::Sha256, typenum::U32);
impl_hasher_trait!(Sha3_512, sha3::Sha3_512, typenum::U64);
impl_hasher_trait!(Ripemd160, ripemd::Ripemd160, typenum::U20);

/////// Streams
pub trait StreamHasher {
    type OutputSize: generic_array::ArrayLength<u8>;

    fn new() -> Self;

    fn write<T: AsRef<[u8]>>(&mut self, in_bytes: T) -> &mut Self;

    fn reset(&mut self);

    fn finalize(&mut self) -> GenericArray<u8, Self::OutputSize>;
}

macro_rules! impl_hasher_stream_trait {
    ($stream_type:ident, $stream_size:ty) => {
        impl StreamHasher for $stream_type {
            type OutputSize = $stream_size;

            fn new() -> Self {
                Self(InternalStreamHasher::new())
            }

            fn write<T: AsRef<[u8]>>(&mut self, in_bytes: T) -> &mut Self {
                self.0.write(in_bytes);
                self
            }

            fn finalize(&mut self) -> GenericArray<u8, Self::OutputSize> {
                self.0.finalize().split().0
            }

            fn reset(&mut self) {
                self.0.reset()
            }
        }
    };
}

#[derive(Clone)]
pub struct Blake2bStream(InternalStreamHasher<blake2::Blake2b<typenum::U64>>);
#[derive(Clone)]
pub struct Blake2b32Stream(InternalStreamHasher<blake2::Blake2b<typenum::U64>>);
#[derive(Clone)]
pub struct Sha1Stream(InternalStreamHasher<sha1::Sha1>);
#[derive(Clone)]
pub struct Sha256Stream(InternalStreamHasher<sha2::Sha256>);
#[derive(Clone)]
pub struct Sha3_512Stream(InternalStreamHasher<sha3::Sha3_512>);
#[derive(Clone)]
pub struct Ripemd160Stream(InternalStreamHasher<ripemd::Ripemd160>);

impl_hasher_stream_trait!(Blake2b32Stream, generic_array::typenum::U32);
impl_hasher_stream_trait!(Blake2bStream, generic_array::typenum::U64);
impl_hasher_stream_trait!(Sha1Stream, generic_array::typenum::U20);
impl_hasher_stream_trait!(Sha256Stream, generic_array::typenum::U32);
impl_hasher_stream_trait!(Sha3_512Stream, generic_array::typenum::U64);
impl_hasher_stream_trait!(Ripemd160Stream, generic_array::typenum::U20);

macro_rules! impl_hasher_stream_with_extra_steps_trait {
    ($stream_type:ident, $final_hash_type:ty, $stream_size:ty) => {
        impl StreamHasher for $stream_type {
            type OutputSize = $stream_size;

            fn new() -> Self {
                Self(InternalStreamHasher::new())
            }

            fn write<T: AsRef<[u8]>>(&mut self, in_bytes: T) -> &mut Self {
                self.0.write(in_bytes);
                self
            }

            fn finalize(&mut self) -> GenericArray<u8, Self::OutputSize> {
                let first_res = self.0.finalize();
                hash::<$final_hash_type, _>(first_res)
            }

            fn reset(&mut self) {
                self.0.reset()
            }
        }
    };
}

pub struct Sha256Ripmd160Stream(InternalStreamHasher<sha2::Sha256>);

impl_hasher_stream_with_extra_steps_trait!(
    Sha256Ripmd160Stream,
    Ripemd160,
    generic_array::typenum::U20
);

/// A generic hash function which will return the hash using the chosen
/// hash algo.
/// expects out_bytes to be the correct size
///
/// currently handles sha1, sha256, sha3, ripemd160 and blake2b
/// DO NOT USE sha1 unless you have a good reason to. It is supported for legacy purposes only
pub fn hash<D: Hasher, T: AsRef<[u8]>>(in_bytes: T) -> GenericArray<u8, <D as Hasher>::OutputSize> {
    D::hash(in_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_blake2b() {
        let exp_res = [
            0x33, 0x3f, 0xcb, 0x4e, 0xe1, 0xaa, 0x7c, 0x11, 0x53, 0x55, 0xec, 0x66, 0xce, 0xac,
            0x91, 0x7c, 0x8b, 0xfd, 0x81, 0x5b, 0xf7, 0x58, 0x7d, 0x32, 0x5a, 0xec, 0x18, 0x64,
            0xed, 0xd2, 0x4e, 0x34, 0xd5, 0xab, 0xe2, 0xc6, 0xb1, 0xb5, 0xee, 0x3f, 0xac, 0xe6,
            0x2f, 0xed, 0x78, 0xdb, 0xef, 0x80, 0x2f, 0x2a, 0x85, 0xcb, 0x91, 0xd4, 0x55, 0xa8,
            0xf5, 0x24, 0x9d, 0x33, 0x08, 0x53, 0xcb, 0x3c,
        ];
        let buf_blake2 = hash::<Blake2b, _>(b"a");
        assert_eq!(buf_blake2.len(), exp_res.len());
        assert!(buf_blake2.iter().zip(exp_res.iter()).all(|(a, b)| a == b));
    }

    #[test]
    fn test_hash_blake2b_stream() {
        let exp_res = [
            0x33, 0x3f, 0xcb, 0x4e, 0xe1, 0xaa, 0x7c, 0x11, 0x53, 0x55, 0xec, 0x66, 0xce, 0xac,
            0x91, 0x7c, 0x8b, 0xfd, 0x81, 0x5b, 0xf7, 0x58, 0x7d, 0x32, 0x5a, 0xec, 0x18, 0x64,
            0xed, 0xd2, 0x4e, 0x34, 0xd5, 0xab, 0xe2, 0xc6, 0xb1, 0xb5, 0xee, 0x3f, 0xac, 0xe6,
            0x2f, 0xed, 0x78, 0xdb, 0xef, 0x80, 0x2f, 0x2a, 0x85, 0xcb, 0x91, 0xd4, 0x55, 0xa8,
            0xf5, 0x24, 0x9d, 0x33, 0x08, 0x53, 0xcb, 0x3c,
        ];
        let mut hasher = Blake2bStream::new();
        hasher.write(b"a");
        let buf_blake2 = hasher.finalize();
        assert_eq!(buf_blake2.len(), exp_res.len());
        assert!(buf_blake2.iter().zip(exp_res.iter()).all(|(a, b)| a == b));
    }

    #[test]
    fn test_hash_sha1() {
        let exp_res = [
            0xaa, 0xec, 0x09, 0x69, 0xb8, 0xf7, 0x7b, 0x8d, 0x63, 0xbc, 0x43, 0xa1, 0x35, 0x2e,
            0x67, 0x5e, 0x9c, 0x86, 0x5e, 0xbd,
        ];
        let buf_sha1 = hash::<Sha1, _>(b"algo");
        assert_eq!(buf_sha1.len(), exp_res.len());
        assert!(buf_sha1.iter().zip(exp_res.iter()).all(|(a, b)| a == b));
    }

    #[test]
    fn test_hash_sha1_stream() {
        let exp_res = [
            0xaa, 0xec, 0x09, 0x69, 0xb8, 0xf7, 0x7b, 0x8d, 0x63, 0xbc, 0x43, 0xa1, 0x35, 0x2e,
            0x67, 0x5e, 0x9c, 0x86, 0x5e, 0xbd,
        ];
        let mut hasher = Sha1Stream::new();
        hasher.write(b"al");
        hasher.write(b"go");
        let buf_sha1 = hasher.finalize();
        assert_eq!(buf_sha1.len(), exp_res.len());
        assert!(buf_sha1.iter().zip(exp_res.iter()).all(|(a, b)| a == b));
    }

    #[test]
    fn test_hash_sha256() {
        let exp_res = [
            0x73, 0x7d, 0xab, 0x86, 0x30, 0x87, 0x72, 0xed, 0x10, 0xfa, 0xe5, 0xe8, 0xf7, 0x57,
            0xb1, 0x85, 0xf0, 0xae, 0x0a, 0x5d, 0x48, 0x5e, 0x0d, 0x27, 0xda, 0xa7, 0xeb, 0x83,
            0x8c, 0x9d, 0x71, 0x69,
        ];
        let buf_sha2 = hash::<Sha256, _>(b"mintlayer");
        assert_eq!(buf_sha2.len(), exp_res.len());
        assert!(buf_sha2.iter().zip(exp_res.iter()).all(|(a, b)| a == b));
    }

    #[test]
    fn test_hash_sha256_stream() {
        let exp_res = [
            0x73, 0x7d, 0xab, 0x86, 0x30, 0x87, 0x72, 0xed, 0x10, 0xfa, 0xe5, 0xe8, 0xf7, 0x57,
            0xb1, 0x85, 0xf0, 0xae, 0x0a, 0x5d, 0x48, 0x5e, 0x0d, 0x27, 0xda, 0xa7, 0xeb, 0x83,
            0x8c, 0x9d, 0x71, 0x69,
        ];
        let mut hasher = Sha256Stream::new();
        hasher.write(b"mint");
        hasher.write(b"layer");
        let buf_sha2 = hasher.finalize();
        assert_eq!(buf_sha2.len(), exp_res.len());
        assert!(buf_sha2.iter().zip(exp_res.iter()).all(|(a, b)| a == b));
    }

    #[test]
    fn test_hash_sha3_512() {
        let exp_res = [
            0xa7, 0x4f, 0x52, 0xdd, 0x84, 0xe8, 0x60, 0x4e, 0xd6, 0x8e, 0xd3, 0xa0, 0x67, 0x9f,
            0xed, 0x7b, 0x7a, 0x09, 0x6a, 0x38, 0xdc, 0xe5, 0x7f, 0xad, 0xc4, 0x82, 0x21, 0x8c,
            0xd9, 0x78, 0x8a, 0x65, 0x71, 0xd5, 0xc5, 0x50, 0x29, 0x90, 0x3d, 0xd3, 0x56, 0x08,
            0x5c, 0x6b, 0x77, 0x07, 0x09, 0x4d, 0x33, 0x6f, 0x96, 0x9a, 0x6a, 0x72, 0xeb, 0xbd,
            0xf8, 0x16, 0x68, 0xf7, 0x11, 0x26, 0x20, 0xa9,
        ];
        let buf_sha3 = hash::<Sha3_512, _>(b"sha3-5");
        assert_eq!(buf_sha3.len(), exp_res.len());
        assert!(buf_sha3.iter().zip(exp_res.iter()).all(|(a, b)| a == b));
    }

    #[test]
    fn test_hash_sha3_512_stream() {
        let exp_res = [
            0xa7, 0x4f, 0x52, 0xdd, 0x84, 0xe8, 0x60, 0x4e, 0xd6, 0x8e, 0xd3, 0xa0, 0x67, 0x9f,
            0xed, 0x7b, 0x7a, 0x09, 0x6a, 0x38, 0xdc, 0xe5, 0x7f, 0xad, 0xc4, 0x82, 0x21, 0x8c,
            0xd9, 0x78, 0x8a, 0x65, 0x71, 0xd5, 0xc5, 0x50, 0x29, 0x90, 0x3d, 0xd3, 0x56, 0x08,
            0x5c, 0x6b, 0x77, 0x07, 0x09, 0x4d, 0x33, 0x6f, 0x96, 0x9a, 0x6a, 0x72, 0xeb, 0xbd,
            0xf8, 0x16, 0x68, 0xf7, 0x11, 0x26, 0x20, 0xa9,
        ];
        let mut hasher = Sha3_512Stream::new();
        hasher.write(b"sha3");
        hasher.write(b"-5");
        let buf_sha3 = hasher.finalize();
        assert_eq!(buf_sha3.len(), exp_res.len());
        assert!(buf_sha3.iter().zip(exp_res.iter()).all(|(a, b)| a == b));
    }

    #[test]
    fn test_ripemd160() {
        let exp_res = [
            0x90, 0x33, 0x91, 0xa1, 0xc0, 0x49, 0x9e, 0xc8, 0xdf, 0xb5, 0x1a, 0x53, 0x4b, 0xa5,
            0x56, 0x57, 0xf9, 0x7c, 0x57, 0xd5,
        ];
        let buf_ripemd160 = hash::<Ripemd160, _>(b"ripemd160");
        assert_eq!(buf_ripemd160.len(), exp_res.len());
        assert!(buf_ripemd160.iter().zip(exp_res.iter()).all(|(a, b)| a == b));
    }

    #[test]
    fn test_ripemd160_stream() {
        let exp_res = [
            0x90, 0x33, 0x91, 0xa1, 0xc0, 0x49, 0x9e, 0xc8, 0xdf, 0xb5, 0x1a, 0x53, 0x4b, 0xa5,
            0x56, 0x57, 0xf9, 0x7c, 0x57, 0xd5,
        ];
        let mut hasher = Ripemd160Stream::new();
        hasher.write(b"ripemd");
        hasher.write(b"160");
        let buf_ripemd160 = hasher.finalize();
        assert_eq!(buf_ripemd160.len(), exp_res.len());
        assert!(buf_ripemd160.iter().zip(exp_res.iter()).all(|(a, b)| a == b));
    }

    #[test]
    /// ripemd160(sha2(data))
    fn bitcoin_public_key_hashing_scheme() {
        let exp_res = [
            174, 183, 216, 205, 49, 68, 162, 107, 201, 149, 236, 151, 159, 218, 170, 44, 33, 144,
            233, 122,
        ];
        let tmp_sha = hash::<Sha256, _>(b"bitcointest");
        let ans = hash::<Ripemd160, _>(tmp_sha);
        assert_eq!(ans.len(), exp_res.len());
        assert!(ans.iter().zip(exp_res.iter()).all(|(a, b)| a == b));
    }

    #[test]
    /// ripemd160(sha2(data))
    fn bitcoin_public_key_hashing_scheme_as_stream() {
        let exp_res = [
            174, 183, 216, 205, 49, 68, 162, 107, 201, 149, 236, 151, 159, 218, 170, 44, 33, 144,
            233, 122,
        ];
        let mut hasher = Sha256Ripmd160Stream::new();
        hasher.write(b"bitcoin");
        hasher.write(b"test");
        let ans = hasher.finalize();
        assert_eq!(ans.len(), exp_res.len());
        assert!(ans.iter().zip(exp_res.iter()).all(|(a, b)| a == b));
    }
}
