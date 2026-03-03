// Copyright (c) 2021-2025 RBB S.r.l
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

mod dump_blocks;
mod error;
mod fields;
#[cfg(test)]
mod tests;
mod utils;

pub use dump_blocks::{dump_blocks_generic, dump_blocks_to_file};
pub use error::Error;
pub use fields::{
    parse_block_output_fields_list, BlockOutputField, DEFAULT_BLOCK_OUTPUT_FIELDS_MAINCHAIN_ONLY,
    DEFAULT_BLOCK_OUTPUT_FIELDS_WITH_STALE_CHAINS,
};
