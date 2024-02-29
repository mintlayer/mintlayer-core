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

use super::{
    IsTokenFreezable, IsTokenFrozen, IsTokenUnfreezable, Metadata, TokenCreator, TokenId,
    TokenTotalSupply,
};
use crate::{
    chain::{Block, Destination, Transaction},
    primitives::{Amount, Id},
};
use rpc_description::ValueHint as VH;
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

    pub fn token_id(&self) -> TokenId {
        match self {
            Self::NonFungibleToken(info) => info.token_id,
            Self::FungibleToken(info) => info.token_id,
        }
    }

    pub fn token_number_of_decimals(&self) -> u8 {
        match self {
            Self::FungibleToken(info) => info.number_of_decimals,
            Self::NonFungibleToken(_) => 0,
        }
    }
}

impl rpc_description::HasValueHint for RPCTokenInfo {
    // TODO This should be more detailed
    const HINT: rpc_description::ValueHint = VH::Choice(&[
        &VH::Object(&[("FungibleToken", &VH::GENERIC_OBJECT)]),
        &VH::Object(&[("NonFungibleToken", &VH::GENERIC_OBJECT)]),
    ]);
}

#[derive(Debug, Clone, Copy, Encode, Decode, serde::Serialize, serde::Deserialize)]
pub enum RPCTokenTotalSupply {
    Fixed(Amount),
    Lockable,
    Unlimited,
}

impl From<TokenTotalSupply> for RPCTokenTotalSupply {
    fn from(value: TokenTotalSupply) -> Self {
        match value {
            TokenTotalSupply::Fixed(v) => RPCTokenTotalSupply::Fixed(v),
            TokenTotalSupply::Lockable => RPCTokenTotalSupply::Lockable,
            TokenTotalSupply::Unlimited => RPCTokenTotalSupply::Unlimited,
        }
    }
}

// Indicates whether a token an be frozen
#[derive(Debug, Copy, Clone, Encode, Decode, serde::Serialize, serde::Deserialize)]
pub enum RPCIsTokenFreezable {
    #[codec(index = 0)]
    No,
    #[codec(index = 1)]
    Yes,
}

impl From<IsTokenFreezable> for RPCIsTokenFreezable {
    fn from(value: IsTokenFreezable) -> Self {
        match value {
            IsTokenFreezable::No => RPCIsTokenFreezable::No,
            IsTokenFreezable::Yes => RPCIsTokenFreezable::Yes,
        }
    }
}

// Indicates whether a token an be unfrozen after being frozen
#[derive(Debug, Copy, Clone, Encode, Decode, serde::Serialize, serde::Deserialize)]
pub enum RPCIsTokenUnfreezable {
    #[codec(index = 0)]
    No,
    #[codec(index = 1)]
    Yes,
}

impl From<IsTokenUnfreezable> for RPCIsTokenUnfreezable {
    fn from(value: IsTokenUnfreezable) -> Self {
        match value {
            IsTokenUnfreezable::No => RPCIsTokenUnfreezable::No,
            IsTokenUnfreezable::Yes => RPCIsTokenUnfreezable::Yes,
        }
    }
}

// Indicates whether a token is frozen at the moment or not. If it is then no operations wish this token can be performed.
// Meaning transfers, burns, minting, unminting, supply locks etc. Frozen token can only be unfrozen
// is such an option was provided while freezing.
#[derive(Debug, Copy, Clone, Encode, Decode, serde::Serialize, serde::Deserialize)]
pub enum RPCIsTokenFrozen {
    #[codec(index = 0)]
    No(RPCIsTokenFreezable),
    #[codec(index = 1)]
    Yes(RPCIsTokenUnfreezable),
}

impl RPCIsTokenFrozen {
    pub fn new(frozen: IsTokenFrozen) -> Self {
        match frozen {
            IsTokenFrozen::No(is_freezable) => Self::No(is_freezable.into()),
            IsTokenFrozen::Yes(is_unfreezable) => Self::Yes(is_unfreezable.into()),
        }
    }
}

#[derive(Debug, Clone, Encode, Decode, serde::Serialize, serde::Deserialize)]
pub struct RPCFungibleTokenInfo {
    // TODO: Add the controller public key to issuance data - https://github.com/mintlayer/mintlayer-core/issues/401
    pub token_id: TokenId,
    pub token_ticker: Vec<u8>,
    pub number_of_decimals: u8,
    pub metadata_uri: Vec<u8>,
    pub circulating_supply: Amount,
    pub total_supply: RPCTokenTotalSupply,
    pub is_locked: bool,
    pub frozen: RPCIsTokenFrozen,
    pub authority: Destination,
}

impl RPCFungibleTokenInfo {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token_id: TokenId,
        token_ticker: Vec<u8>,
        number_of_decimals: u8,
        metadata_uri: Vec<u8>,
        circulating_supply: Amount,
        total_supply: RPCTokenTotalSupply,
        is_locked: bool,
        frozen: RPCIsTokenFrozen,
        authority: Destination,
    ) -> Self {
        Self {
            token_id,
            token_ticker,
            number_of_decimals,
            metadata_uri,
            circulating_supply,
            total_supply,
            is_locked,
            frozen,
            authority,
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
