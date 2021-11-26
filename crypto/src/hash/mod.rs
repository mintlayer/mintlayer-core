mod internal;
use generic_array::{typenum, ArrayLength, GenericArray};

pub trait Hasher {
    type OutputSize: ArrayLength<u8>;

    fn hash<T: AsRef<[u8]>>(data: T) -> GenericArray<u8, Self::OutputSize>;
}

pub struct Blake2b;
pub struct Sha1;
pub struct Sha256;
pub struct Sha3_512;
pub struct Ripemd160;

#[derive(Debug, Clone, PartialEq)]
pub struct Hash256([u8;32]); //TODO: change this temporary holder to an actual one

impl Hasher for Blake2b {
    type OutputSize = typenum::U64;

    fn hash<T: AsRef<[u8]>>(data: T) -> GenericArray<u8, Self::OutputSize> {
        internal::hash::<hashing::blake2::Blake2b, T>(data)
    }
}

impl Hasher for Sha1 {
    type OutputSize = typenum::U20;

    fn hash<T: AsRef<[u8]>>(data: T) -> GenericArray<u8, Self::OutputSize> {
        internal::hash::<hashing::sha1::Sha1, T>(data)
    }
}

impl Hasher for Sha256 {
    type OutputSize = typenum::U32;

    fn hash<T: AsRef<[u8]>>(data: T) -> GenericArray<u8, Self::OutputSize> {
        internal::hash::<hashing::sha2::Sha256, T>(data)
    }
}

impl Hasher for Sha3_512 {
    type OutputSize = typenum::U64;

    fn hash<T: AsRef<[u8]>>(data: T) -> GenericArray<u8, Self::OutputSize> {
        internal::hash::<hashing::sha3::Sha3_512, T>(data)
    }
}

impl Hasher for Ripemd160 {
    type OutputSize = typenum::U20;

    fn hash<T: AsRef<[u8]>>(data: T) -> GenericArray<u8, Self::OutputSize> {
        internal::hash::<hashing::ripemd160::Ripemd160, T>(data)
    }
}

/// A generic hash function which will return the hash using the chosen
/// hash algo.
/// expects out_bytes to be the correct size
///
/// currently handles sha1, sha256, sha3, ripemd160 and blake2b
/// DO NOT USE sha1 unless you have a good reason to. It is supported for legacy purposes only
pub fn hash<D: Hasher, T: AsRef<[u8]>>(in_bytes: T) -> GenericArray<u8, <D as Hasher>::OutputSize> {
    D::hash(in_bytes)
}

#[test]
fn test_hash_blake2b() {
    let exp_res = [
        0x33, 0x3f, 0xcb, 0x4e, 0xe1, 0xaa, 0x7c, 0x11, 0x53, 0x55, 0xec, 0x66, 0xce, 0xac, 0x91,
        0x7c, 0x8b, 0xfd, 0x81, 0x5b, 0xf7, 0x58, 0x7d, 0x32, 0x5a, 0xec, 0x18, 0x64, 0xed, 0xd2,
        0x4e, 0x34, 0xd5, 0xab, 0xe2, 0xc6, 0xb1, 0xb5, 0xee, 0x3f, 0xac, 0xe6, 0x2f, 0xed, 0x78,
        0xdb, 0xef, 0x80, 0x2f, 0x2a, 0x85, 0xcb, 0x91, 0xd4, 0x55, 0xa8, 0xf5, 0x24, 0x9d, 0x33,
        0x08, 0x53, 0xcb, 0x3c,
    ];
    let buf_blake2 = hash::<Blake2b, _>((b"a").to_vec());
    assert_eq!(buf_blake2.len(), exp_res.len());
    assert!(buf_blake2.iter().zip(exp_res.iter()).all(|(a, b)| a == b));
}

#[test]
fn test_hash_sha1() {
    let exp_res = [
        0xaa, 0xec, 0x09, 0x69, 0xb8, 0xf7, 0x7b, 0x8d, 0x63, 0xbc, 0x43, 0xa1, 0x35, 0x2e, 0x67,
        0x5e, 0x9c, 0x86, 0x5e, 0xbd,
    ];
    let buf_sha1 = hash::<Sha1, _>((b"algo").to_vec());
    assert_eq!(buf_sha1.len(), exp_res.len());
    assert!(buf_sha1.iter().zip(exp_res.iter()).all(|(a, b)| a == b));
}

#[test]
fn test_hash_sha256() {
    let exp_res = [
        0x73, 0x7d, 0xab, 0x86, 0x30, 0x87, 0x72, 0xed, 0x10, 0xfa, 0xe5, 0xe8, 0xf7, 0x57, 0xb1,
        0x85, 0xf0, 0xae, 0x0a, 0x5d, 0x48, 0x5e, 0x0d, 0x27, 0xda, 0xa7, 0xeb, 0x83, 0x8c, 0x9d,
        0x71, 0x69,
    ];
    let buf_sha2 = hash::<Sha256, _>((b"mintlayer").to_vec());
    assert_eq!(buf_sha2.len(), exp_res.len());
    assert!(buf_sha2.iter().zip(exp_res.iter()).all(|(a, b)| a == b));
}

#[test]
fn test_hash_sha3_512() {
    let exp_res = [
        0xa7, 0x4f, 0x52, 0xdd, 0x84, 0xe8, 0x60, 0x4e, 0xd6, 0x8e, 0xd3, 0xa0, 0x67, 0x9f, 0xed,
        0x7b, 0x7a, 0x09, 0x6a, 0x38, 0xdc, 0xe5, 0x7f, 0xad, 0xc4, 0x82, 0x21, 0x8c, 0xd9, 0x78,
        0x8a, 0x65, 0x71, 0xd5, 0xc5, 0x50, 0x29, 0x90, 0x3d, 0xd3, 0x56, 0x08, 0x5c, 0x6b, 0x77,
        0x07, 0x09, 0x4d, 0x33, 0x6f, 0x96, 0x9a, 0x6a, 0x72, 0xeb, 0xbd, 0xf8, 0x16, 0x68, 0xf7,
        0x11, 0x26, 0x20, 0xa9,
    ];
    let buf_sha3 = hash::<Sha3_512, _>((b"sha3-5").to_vec());
    assert_eq!(buf_sha3.len(), exp_res.len());
    assert!(buf_sha3.iter().zip(exp_res.iter()).all(|(a, b)| a == b));
}

#[test]
fn test_ripemd160() {
    let exp_res = [
        0x90, 0x33, 0x91, 0xa1, 0xc0, 0x49, 0x9e, 0xc8, 0xdf, 0xb5, 0x1a, 0x53, 0x4b, 0xa5, 0x56,
        0x57, 0xf9, 0x7c, 0x57, 0xd5,
    ];
    let buf_ripemd160 = hash::<Ripemd160, _>((b"ripemd160").to_vec());
    assert_eq!(buf_ripemd160.len(), exp_res.len());
    assert!(buf_ripemd160.iter().zip(exp_res.iter()).all(|(a, b)| a == b));
}

#[test]
/// ripemd160(sha2(data))
fn bitcoin_public_key_hashing_scheme() {
    let exp_res = [
        174, 183, 216, 205, 49, 68, 162, 107, 201, 149, 236, 151, 159, 218, 170, 44, 33, 144, 233,
        122,
    ];
    let tmp_sha = hash::<Sha256, _>((b"bitcointest").to_vec());
    let ans = hash::<Ripemd160, _>(tmp_sha);
    assert_eq!(ans.len(), exp_res.len());
    assert!(ans.iter().zip(exp_res.iter()).all(|(a, b)| a == b));
}
