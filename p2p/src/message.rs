// Copyright (c) 2021 RBB S.r.l
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

use chainstate::Locator;
use common::{
    chain::block::{Block, BlockHeader},
    primitives::Id,
};
use serialization::{Decode, Encode};

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct HeaderRequest {
    locator: Locator,
}

impl HeaderRequest {
    pub fn new(locator: Locator) -> Self {
        HeaderRequest { locator }
    }

    pub fn locator(&self) -> &Locator {
        &self.locator
    }

    pub fn into_locator(self) -> Locator {
        self.locator
    }
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct BlockRequest {
    block_ids: Vec<Id<Block>>,
}

impl BlockRequest {
    pub fn new(block_ids: Vec<Id<Block>>) -> Self {
        Self { block_ids }
    }

    pub fn block_ids(&self) -> &Vec<Id<Block>> {
        &self.block_ids
    }

    pub fn into_block_ids(self) -> Vec<Id<Block>> {
        self.block_ids
    }
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum Request {
    #[codec(index = 0)]
    HeaderRequest(HeaderRequest),
    #[codec(index = 1)]
    BlockRequest(BlockRequest),
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct HeaderListResponse {
    headers: Vec<BlockHeader>,
}

impl HeaderListResponse {
    pub fn new(headers: Vec<BlockHeader>) -> Self {
        Self { headers }
    }

    pub fn headers(&self) -> &Vec<BlockHeader> {
        &self.headers
    }

    pub fn into_headers(self) -> Vec<BlockHeader> {
        self.headers
    }
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct BlockListResponse {
    blocks: Vec<Block>,
}

impl BlockListResponse {
    pub fn new(blocks: Vec<Block>) -> Self {
        Self { blocks }
    }

    pub fn blocks(&self) -> &Vec<Block> {
        &self.blocks
    }

    pub fn into_blocks(self) -> Vec<Block> {
        self.blocks
    }
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum Response {
    #[codec(index = 0)]
    HeaderResponse(HeaderListResponse),
    #[codec(index = 1)]
    BlockResponse(BlockListResponse),
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum Announcement {
    #[codec(index = 0)]
    Block(Block),
}
