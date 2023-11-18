// Copyright (c) 2021-2023 RBB S.r.l
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

use blake2::digest::{generic_array::GenericArray, typenum, Digest};
use fixed_hash::construct_fixed_hash;

use crate::hasher::PairHasher;

construct_fixed_hash! {
    pub struct HashedData(32);
}

type Blake2bHasher = blake2::Blake2b<typenum::U32>;

#[derive(Clone)]
pub struct HashAlgo(Blake2bHasher);

impl HashAlgo {
    pub fn new() -> Self {
        Self(Blake2bHasher::new())
    }

    pub fn write<T: AsRef<[u8]>>(&mut self, in_bytes: T) {
        Digest::update(&mut self.0, in_bytes);
    }

    pub fn finalize(&mut self) -> HashedData {
        self.0.finalize_reset().into()
    }
}

pub fn hash_data<T: AsRef<[u8]> + Clone>(data: T) -> HashedData {
    let mut h = Blake2bHasher::new();
    Digest::update(&mut h, data);
    h.finalize_reset().into()
}

// pub type HashAlgoStream = crypto::hash::Blake2b32Stream;

impl From<GenericArray<u8, typenum::U32>> for HashedData {
    fn from(val: GenericArray<u8, typenum::U32>) -> Self {
        Self(val.into())
    }
}

impl PairHasher for HashAlgo {
    type Type = HashedData;

    fn hash_pair(left: &Self::Type, right: &Self::Type) -> Self::Type {
        let mut h = Blake2bHasher::new();
        Digest::update(&mut h, left);
        Digest::update(&mut h, right);
        h.finalize_reset().into()
    }

    fn hash_single(data: &Self::Type) -> Self::Type {
        let mut h = Blake2bHasher::new();
        Digest::update(&mut h, data);
        h.finalize_reset().into()
    }
}
