// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): S. Afach

use generic_array::typenum::marker_traits::Unsigned;

fixed_hash::construct_fixed_hash! {
    pub struct H256(32);
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Id<T: ?Sized> {
    id: H256,
    _shadow: std::marker::PhantomData<T>,
}

impl<T> Id<T> {
    pub fn get(&self) -> H256 {
        self.id
    }

    pub fn new(h: &H256) -> Self {
        Self {
            id: *h,
            _shadow: std::marker::PhantomData,
        }
    }
}

/// a trait for objects that deserve having a unique id with implementations to how to ID them
pub trait Idable<T: ?Sized> {
    fn get_id(&self) -> Id<Self>;
}

#[allow(dead_code)]
pub type DataID = H256;

// we use a cropping stream (64 => 32) because
// we want a hash result to H256 and a byte array
// of the hash to be identical, while benefiting
// from a strong and software-friendly hash function;
// both the hashing methods below should produce the
// same result
pub type DefaultHashAlgo = crypto::hash::Blake2b;
pub type DefaultHashAlgoStream = crypto::hash::Blake2bStream32;

pub fn default_hash<T: AsRef<[u8]> + Clone>(data: T) -> H256 {
    let d = crypto::hash::hash::<DefaultHashAlgo, _>(&data);
    H256::from(d.as_slice())
}

impl From<&[u8]> for H256 {
    fn from(data: &[u8]) -> Self {
        // since we're gonna do a copy from some data to H256,
        // let's ensure that we won't have unused parts in H256 at compile-time
        static_assertions::const_assert!(
            <<DefaultHashAlgoStream as crypto::hash::StreamHasher>::OutputSize as Unsigned>::USIZE
                >= H256::len_bytes()
        );
        static_assertions::const_assert!(
            <<DefaultHashAlgo as crypto::hash::Hasher>::OutputSize as Unsigned>::USIZE
                >= H256::len_bytes()
        );

        H256::from_slice(&data[..H256::len_bytes()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::hash::StreamHasher;

    #[test]
    fn basic_h256_to_and_from_bytes() {
        use rand::Rng;
        let random_bytes = rand::thread_rng().gen::<[u8; H256::len_bytes()]>();

        let n = H256::from(random_bytes);
        let bytes_again = n.as_bytes().clone();
        assert_eq!(n.as_bytes(), random_bytes);
        let m = H256::from(bytes_again);
        assert_eq!(m, n);
    }

    #[test]
    fn hashes_stream_and_msg_identical() {
        use rand::Rng;
        let random_bytes = rand::thread_rng().gen::<[u8; H256::len_bytes()]>();

        let h1 = default_hash(random_bytes);
        let mut hash_stream = DefaultHashAlgoStream::new();
        hash_stream.write(random_bytes);
        let h2 = hash_stream.finalize();

        assert_eq!(h1, H256::from(h2.as_slice()));

        let h3 = crypto::hash::hash::<DefaultHashAlgo, _>(&random_bytes);

        assert_eq!(h1, H256::from(h3.as_slice()));
    }
}
