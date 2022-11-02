// Copyright (c) 2022 RBB S.r.l
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

pub mod storage_result;

pub use crate::{
    ancestor::block_index_ancestor_getter, ancestor::gen_block_index_getter,
    block_index::BlockIndex, block_index_handle::BlockIndexHandle, error::GetAncestorError,
    error::PropertyQueryError, gen_block_index::GenBlockIndex, height_skip::get_skip_height,
    locator::Locator,
};

mod ancestor;
mod block_index;
mod block_index_handle;
mod error;
mod gen_block_index;
mod height_skip;
mod locator;
