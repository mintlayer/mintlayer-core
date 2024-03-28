// Copyright (c) 2021-2024 RBB S.r.l
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

use chainstate_types::BlockIndex;
use common::{
    chain::{
        block::{signed_block_header::SignedBlockHeader, BlockHeader},
        Block,
    },
    primitives::{id::WithId, Id, Idable},
};

/// A block header together with its (probably pre-computed) id.
// Note: we don't want this trait to be mis- or over-used, so we use `pub(super)` to limit its
// scope to `chainstateref`. And requiring `Sized` is a reminder that it's not supposed to be used
// with `dyn`.
pub(super) trait BlockInfo: Sized {
    /// Get the block id; this may be cheaper than calling get_id on the header (which would
    /// calculate the id from the header data).
    fn get_or_calc_id(&self) -> Id<Block>;

    /// Get the header.
    fn get_header(&self) -> &BlockHeader;
}

impl BlockInfo for BlockIndex {
    fn get_or_calc_id(&self) -> Id<Block> {
        *self.block_id()
    }

    fn get_header(&self) -> &BlockHeader {
        self.block_header().header()
    }
}

impl BlockInfo for SignedBlockHeader {
    fn get_or_calc_id(&self) -> Id<Block> {
        self.get_id()
    }

    fn get_header(&self) -> &BlockHeader {
        self.header()
    }
}

impl BlockInfo for BlockHeader {
    fn get_or_calc_id(&self) -> Id<Block> {
        self.get_id()
    }

    fn get_header(&self) -> &BlockHeader {
        self
    }
}

impl<T> BlockInfo for WithId<T>
where
    T: Idable<Tag = Block> + BlockInfo,
{
    fn get_or_calc_id(&self) -> Id<Block> {
        WithId::<T>::get(self).get_id()
    }

    fn get_header(&self) -> &BlockHeader {
        WithId::<T>::get(self).get_header()
    }
}
