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

use crate::Uint256;
use generic_array::{typenum, GenericArray};
use parity_scale_codec::{Decode, Encode};

fixed_hash::construct_fixed_hash! {
    #[derive(Encode, Decode)]
    pub struct H256(32);
}

impl From<GenericArray<u8, typenum::U32>> for H256 {
    fn from(val: GenericArray<u8, typenum::U32>) -> Self {
        Self(val.into())
    }
}

impl H256 {
    fn reverse_inner(&self) -> [u8; 32] {
        let mut h256_inner = self.0;
        h256_inner.reverse();
        h256_inner
    }
}

impl From<H256> for Uint256 {
    fn from(hash: H256) -> Self {
        let x = hash.reverse_inner();
        Uint256::from_be_bytes(x)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
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

impl<T> AsRef<[u8]> for Id<T> {
    fn as_ref(&self) -> &[u8] {
        &self.id[..]
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

    #[test]
    fn hashes_stream_and_msg_identical() {
        use rand::Rng;
        let random_bytes = rand::thread_rng().gen::<[u8; H256::len_bytes()]>();

        let h1 = default_hash(random_bytes);
        let mut hash_stream = DefaultHashAlgoStream::new();
        hash_stream.write(random_bytes);
        let h2 = hash_stream.finalize();

        assert_eq!(h1, h2.into());

        let h3 = crypto::hash::hash::<DefaultHashAlgo, _>(&random_bytes);

        assert_eq!(h1, h3.into());
    }
}
