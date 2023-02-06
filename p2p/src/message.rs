// Copyright (c) 2021-2022 RBB S.r.l
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

use crate::types::peer_address::PeerAddress;

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct HeaderListRequest {
    locator: Locator,
}

impl HeaderListRequest {
    pub fn new(locator: Locator) -> Self {
        HeaderListRequest { locator }
    }

    pub fn locator(&self) -> &Locator {
        &self.locator
    }

    pub fn into_locator(self) -> Locator {
        self.locator
    }
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct BlockListRequest {
    block_ids: Vec<Id<Block>>,
}

impl BlockListRequest {
    pub fn new(block_ids: Vec<Id<Block>>) -> Self {
        Self { block_ids }
    }

    pub fn block_ids(&self) -> &[Id<Block>] {
        &self.block_ids
    }

    pub fn into_block_ids(self) -> Vec<Id<Block>> {
        self.block_ids
    }
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct AddrListRequest {}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct AnnounceAddrRequest {
    pub address: PeerAddress,
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct PingRequest {
    pub nonce: u64,
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum Request {
    #[codec(index = 0)]
    HeaderListRequest(HeaderListRequest),
    #[codec(index = 1)]
    BlockListRequest(BlockListRequest),
    #[codec(index = 2)]
    AddrListRequest(AddrListRequest),
    #[codec(index = 3)]
    AnnounceAddrRequest(AnnounceAddrRequest),
    #[codec(index = 4)]
    PingRequest(PingRequest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncRequest {
    HeaderListRequest(HeaderListRequest),
    BlockListRequest(BlockListRequest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerManagerRequest {
    AddrListRequest(AddrListRequest),
    AnnounceAddrRequest(AnnounceAddrRequest),
    PingRequest(PingRequest),
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct HeaderListResponse {
    headers: Vec<BlockHeader>,
}

impl HeaderListResponse {
    pub fn new(headers: Vec<BlockHeader>) -> Self {
        Self { headers }
    }

    pub fn headers(&self) -> &[BlockHeader] {
        &self.headers
    }

    pub fn into_headers(self) -> Vec<BlockHeader> {
        self.headers
    }
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct BlockResponse {
    block: Block,
}

impl BlockResponse {
    pub fn new(block: Block) -> Self {
        Self { block }
    }

    pub fn block(&self) -> &Block {
        &self.block
    }

    pub fn into_block(self) -> Block {
        self.block
    }
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct AnnounceAddrResponse {}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct AddrListResponse {
    pub addresses: Vec<PeerAddress>,
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct PingResponse {
    pub nonce: u64,
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum Response {
    #[codec(index = 0)]
    HeaderListResponse(HeaderListResponse),
    #[codec(index = 1)]
    BlockResponse(BlockResponse),
    #[codec(index = 2)]
    AddrListResponse(AddrListResponse),
    #[codec(index = 3)]
    AnnounceAddrResponse(AnnounceAddrResponse),
    #[codec(index = 4)]
    PingResponse(PingResponse),
}

#[derive(Debug, Clone)]
pub enum SyncResponse {
    /// This message is sent as a response to `HeaderListRequest`.
    HeaderListResponse(HeaderListResponse),
    /// This message contains a single block, so multiple such messages can be sent as a response
    /// to BlockListRequest.
    BlockResponse(BlockResponse),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerManagerResponse {
    AddrListResponse(AddrListResponse),
    AnnounceAddrResponse(AnnounceAddrResponse),
    PingResponse(PingResponse),
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum Announcement {
    #[codec(index = 0)]
    Block(BlockHeader),
}

impl From<PeerManagerRequest> for Request {
    fn from(request: PeerManagerRequest) -> Self {
        match request {
            PeerManagerRequest::AddrListRequest(request) => Request::AddrListRequest(request),
            PeerManagerRequest::AnnounceAddrRequest(request) => {
                Request::AnnounceAddrRequest(request)
            }
            PeerManagerRequest::PingRequest(request) => Request::PingRequest(request),
        }
    }
}

impl From<PeerManagerResponse> for Response {
    fn from(response: PeerManagerResponse) -> Self {
        match response {
            PeerManagerResponse::AddrListResponse(response) => Response::AddrListResponse(response),
            PeerManagerResponse::AnnounceAddrResponse(response) => {
                Response::AnnounceAddrResponse(response)
            }
            PeerManagerResponse::PingResponse(response) => Response::PingResponse(response),
        }
    }
}

impl From<SyncRequest> for Request {
    fn from(request: SyncRequest) -> Self {
        match request {
            SyncRequest::HeaderListRequest(request) => Request::HeaderListRequest(request),
            SyncRequest::BlockListRequest(request) => Request::BlockListRequest(request),
        }
    }
}

impl From<SyncResponse> for Response {
    fn from(response: SyncResponse) -> Self {
        match response {
            SyncResponse::HeaderListResponse(response) => Response::HeaderListResponse(response),
            SyncResponse::BlockResponse(response) => Response::BlockResponse(response),
        }
    }
}
