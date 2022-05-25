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
// Author(s): A. Altonen
use common::{
    chain::block::{Block, BlockHeader},
    primitives::{Id, Idable},
};
use serialization::{Decode, Encode};

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum SyncingRequest {
    #[codec(index = 0)]
    GetHeaders { locator: Vec<BlockHeader> },
    #[codec(index = 1)]
    GetBlocks { block_ids: Vec<Id<Block>> },
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum SyncingResponse {
    #[codec(index = 0)]
    Headers { headers: Vec<BlockHeader> },
    #[codec(index = 1)]
    Blocks { blocks: Vec<Block> },
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum PubSubMessage {
    #[codec(index = 0)]
    Block(Block),
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum SyncingMessage {
    #[codec(index = 0)]
    Request(SyncingRequest),
    #[codec(index = 1)]
    Response(SyncingResponse),
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum MessageType {
    #[codec(index = 0)]
    Syncing(SyncingMessage),
    #[codec(index = 1)]
    PubSub(PubSubMessage),
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
#[allow(unused)]
pub struct Message {
    /// Magic number identifying mainnet, testnet
    pub magic: [u8; 4],

    /// Message (GetHeaders, Blocks, etc.)
    pub msg: MessageType,
}
