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

use super::{Metadata, TokenCreator, TokenId};
use crate::{
    chain::{Block, Transaction},
    primitives::{Amount, Id},
};
use serialization::{Decode, Encode};

#[derive(Debug, Clone, Encode, Decode, serde::Serialize, serde::Deserialize)]

pub enum RPCTokenInfo {
    FungibleToken(RPCFungibleTokenInfo),
    NonFungibleToken(Box<RPCNonFungibleTokenInfo>),
}

impl RPCTokenInfo {
    pub fn new_fungible(token_info: RPCFungibleTokenInfo) -> Self {
        Self::FungibleToken(token_info)
    }

    pub fn new_nonfungible(token_info: RPCNonFungibleTokenInfo) -> Self {
        Self::NonFungibleToken(Box::new(token_info))
    }
}

#[derive(Debug, Clone, Encode, Decode, serde::Serialize, serde::Deserialize)]
pub struct RPCFungibleTokenInfo {
    // TODO: Add the controller public key to issuance data - https://github.com/mintlayer/mintlayer-core/issues/401
    pub token_id: TokenId,
    pub creation_tx_id: Id<Transaction>,
    pub creation_block_id: Id<Block>,
    pub token_ticker: Vec<u8>,
    pub amount_to_issue: Amount,
    pub number_of_decimals: u8,
    pub metadata_uri: Vec<u8>,
}

impl RPCFungibleTokenInfo {
    pub fn new(
        token_id: TokenId,
        creation_tx_id: Id<Transaction>,
        creation_block_id: Id<Block>,
        token_ticker: Vec<u8>,
        amount_to_issue: Amount,
        number_of_decimals: u8,
        metadata_uri: Vec<u8>,
    ) -> Self {
        Self {
            token_id,
            creation_tx_id,
            creation_block_id,
            token_ticker,
            amount_to_issue,
            number_of_decimals,
            metadata_uri,
        }
    }
}

#[derive(Debug, Clone, Encode, Decode, serde::Serialize, serde::Deserialize)]
pub struct RPCNonFungibleTokenInfo {
    pub token_id: TokenId,
    pub creation_tx_id: Id<Transaction>,
    pub creation_block_id: Id<Block>,
    pub metadata: RPCNonFungibleTokenMetadata,
}

impl RPCNonFungibleTokenInfo {
    pub fn new(
        token_id: TokenId,
        creation_tx_id: Id<Transaction>,
        creation_block_id: Id<Block>,
        metadata: &Metadata,
    ) -> Self {
        Self {
            token_id,
            creation_tx_id,
            creation_block_id,
            metadata: RPCNonFungibleTokenMetadata::from(metadata),
        }
    }
}

#[derive(Debug, Clone, Encode, Decode, serde::Serialize, serde::Deserialize)]
pub struct RPCTokenCreator(Vec<u8>);

impl From<&TokenCreator> for RPCTokenCreator {
    fn from(creator: &TokenCreator) -> Self {
        // None-RPC type mustn't have serde requirements
        RPCTokenCreator(creator.encode())
    }
}

#[derive(Debug, Clone, Encode, Decode, serde::Serialize, serde::Deserialize)]
pub struct RPCNonFungibleTokenMetadata {
    pub creator: Option<RPCTokenCreator>,
    pub name: Vec<u8>,
    pub description: Vec<u8>,
    pub ticker: Vec<u8>,
    pub icon_uri: Vec<u8>,
    pub additional_metadata_uri: Vec<u8>,
    pub media_uri: Vec<u8>,
    pub media_hash: Vec<u8>,
}

impl From<&Metadata> for RPCNonFungibleTokenMetadata {
    fn from(metadata: &Metadata) -> Self {
        Self {
            creator: metadata.creator().as_ref().map(RPCTokenCreator::from),
            name: metadata.name().clone(),
            description: metadata.description().clone(),
            ticker: metadata.ticker().clone(),
            icon_uri: metadata.icon_uri().encode(),
            additional_metadata_uri: metadata.additional_metadata_uri().encode(),
            media_uri: metadata.media_uri().encode(),
            media_hash: metadata.media_hash().clone(),
        }
    }
}
