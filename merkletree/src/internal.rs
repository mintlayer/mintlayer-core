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

use crypto::hash::StreamHasher;
use fixed_hash::construct_fixed_hash;
use generic_array::{typenum, GenericArray};

use crate::hasher::PairHasher;

construct_fixed_hash! {
    pub struct HashedData(32);
}

#[cfg(test)]
pub type HashAlgo = crypto::hash::Blake2b32;

#[cfg(test)]
pub fn hash_data<T: AsRef<[u8]> + Clone>(data: T) -> HashedData {
    crypto::hash::hash::<HashAlgo, _>(&data).into()
}

pub type HashAlgoStream = crypto::hash::Blake2b32Stream;

impl From<GenericArray<u8, typenum::U32>> for HashedData {
    fn from(val: GenericArray<u8, typenum::U32>) -> Self {
        Self(val.into())
    }
}

impl PairHasher for HashAlgoStream {
    type Type = HashedData;

    fn hash_pair(left: &Self::Type, right: &Self::Type) -> Self::Type {
        let mut hasher = HashAlgoStream::new();
        hasher.write(left);
        hasher.write(right);
        hasher.finalize().into()
    }

    fn hash_single(data: &Self::Type) -> Self::Type {
        let mut hasher = HashAlgoStream::new();
        hasher.write(data);
        hasher.finalize().into()
    }
}
