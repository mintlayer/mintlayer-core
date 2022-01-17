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
// Author(s): Anton Sinitsyn

use common::primitives::{BlockHeight, H256};
use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockStatus {
    Valid,
    Failed,
    // To be expanded
}

#[allow(dead_code)]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum BlockError {
    #[error("Unknown error")]
    Unknown,
    // To be expanded
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code, unused_variables)]
pub struct BlockIndex {
    hash_block: H256,
    prev_block: H256,
    status: BlockStatus,
    height: BlockHeight,
}

impl BlockIndex {
    pub fn new() -> Self {
        Self {
            hash_block: H256::zero(),
            prev_block: H256::zero(),
            status: BlockStatus::Failed,
            height: BlockHeight::new(0),
        }
    }
}
