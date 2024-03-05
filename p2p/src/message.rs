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
    chain::{
        block::{signed_block_header::SignedBlockHeader, Block},
        SignedTransaction, Transaction,
    },
    primitives::Id,
};
use serialization::{Decode, Encode};

use crate::types::peer_address::PeerAddress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockSyncMessage {
    HeaderListRequest(HeaderListRequest),
    BlockListRequest(BlockListRequest),
    HeaderList(HeaderList),
    BlockResponse(BlockResponse),

    // A "sentinel" message for testing purposes that allows to ensure that all block sync messages
    // that were sent into a channel have been processed by the receiver.
    // When the sync manager receives it, it should simply send it "back" via MessagingService.
    // TODO: it would be nice to refactor tests that depend on this, so that it can be removed.
    #[cfg(test)]
    TestSentinel(Id<()>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionSyncMessage {
    NewTransaction(Id<Transaction>),
    TransactionRequest(Id<Transaction>),
    TransactionResponse(TransactionResponse),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerManagerMessage {
    AddrListRequest(AddrListRequest),
    AnnounceAddrRequest(AnnounceAddrRequest),
    PingRequest(PingRequest),
    AddrListResponse(AddrListResponse),
    PingResponse(PingResponse),
    WillDisconnect(WillDisconnectMessage),
}

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

/// A list of block headers.
///
/// This messages is sent as a response to the the `HeaderListRequest` message or as a new block
/// announcement.
#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct HeaderList {
    headers: Vec<SignedBlockHeader>,
}

impl HeaderList {
    pub fn new(headers: Vec<SignedBlockHeader>) -> Self {
        Self { headers }
    }

    pub fn headers(&self) -> &[SignedBlockHeader] {
        &self.headers
    }

    pub fn into_headers(self) -> Vec<SignedBlockHeader> {
        self.headers
    }
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct BlockResponse {
    block: Box<Block>,
}

impl BlockResponse {
    pub fn new(block: Block) -> Self {
        Self {
            block: Box::new(block),
        }
    }

    pub fn block(&self) -> &Block {
        &self.block
    }

    pub fn into_block(self) -> Block {
        *self.block
    }
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum TransactionResponse {
    #[codec(index = 0)]
    NotFound(Id<Transaction>),
    #[codec(index = 1)]
    Found(SignedTransaction),
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct AddrListResponse {
    pub addresses: Vec<PeerAddress>,
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct PingResponse {
    pub nonce: u64,
}

// Note: 'reason' is a string here, because we want to be able to add more reasons without upping
// the protocol version.
#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct WillDisconnectMessage {
    pub reason: String,
}
