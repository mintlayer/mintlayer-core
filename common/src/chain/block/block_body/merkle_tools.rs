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
use merkletree::hasher::PairHasher;

use crate::primitives::{id::DefaultHashAlgoStream, H256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MerkleHasher {}

impl PairHasher for MerkleHasher {
    type Type = H256;

    fn hash_pair(left: &Self::Type, right: &Self::Type) -> Self::Type {
        let mut hasher = DefaultHashAlgoStream::new();
        hasher.write(left);
        hasher.write(right);
        hasher.finalize().into()
    }

    fn hash_single(data: &Self::Type) -> Self::Type {
        let mut hasher = DefaultHashAlgoStream::new();
        hasher.write(data);
        hasher.finalize().into()
    }
}
