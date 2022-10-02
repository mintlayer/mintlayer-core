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

use serialization::{Decode, Encode};

pub type TokenId = H256;
pub type NftDataHash = Vec<u8>;
use crate::primitives::{Amount, Id, H256};

mod nft;
mod rpc;
mod tokens_utils;

pub use nft::*;
pub use rpc::*;
pub use tokens_utils::*;

use super::{Block, Transaction};

/// The data that is created when a token is issued to track it (and to update it with ACL commands)
#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq)]
pub struct TokenAuxiliaryData {
    issuance_tx: Transaction,
    issuance_block_id: Id<Block>,
}

impl TokenAuxiliaryData {
    pub fn new(issuance_tx: Transaction, issuance_block_id: Id<Block>) -> Self {
        Self {
            issuance_tx,
            issuance_block_id,
        }
    }

    pub fn issuance_tx(&self) -> &Transaction {
        &self.issuance_tx
    }

    pub fn issuance_block_id(&self) -> Id<Block> {
        self.issuance_block_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
#[allow(clippy::large_enum_variant)]
pub enum OutputValue {
    Coin(Amount),
    //FIXME(nft_issuance): Clippy warning on this. Should we use Box here?
    Token(TokenData),
}

impl OutputValue {
    pub fn coin_amount(&self) -> Option<Amount> {
        match self {
            OutputValue::Coin(v) => Some(*v),
            OutputValue::Token(_) => None,
        }
    }

    pub fn token_data(&self) -> Option<&TokenData> {
        match self {
            OutputValue::Coin(_) => None,
            OutputValue::Token(d) => Some(d),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct TokenTransferV1 {
    pub token_id: TokenId,
    // Todo(nft_issuance): Should we use enum here, to choose NFT or tokens?
    pub amount: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct TokenIssuanceV1 {
    pub token_ticker: Vec<u8>,
    pub amount_to_issue: Amount,
    pub number_of_decimals: u8,
    pub metadata_uri: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct TokenBurnV1 {
    pub token_id: TokenId,
    pub amount_to_burn: Amount,
}

//FIXME(nft_issuance): Clippy warning on this. Should we use Box here?
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
#[allow(clippy::large_enum_variant)]
pub enum TokenData {
    /// TokenTransfer data to another user. If it is a token, then the token data must also be transferred to the recipient.
    #[codec(index = 1)]
    TokenTransferV1(TokenTransferV1),
    /// New token creation
    #[codec(index = 2)]
    TokenIssuanceV1(TokenIssuanceV1),
    /// Burning a token or NFT
    #[codec(index = 3)]
    TokenBurnV1(TokenBurnV1),
    // A new NFT creation
    #[codec(index = 4)]
    NftIssuanceV1(NftIssuanceV1),
    // TODO: These types will be implemented in the future PRs
    // // Increase amount of tokens
    // #[codec(index = 4)]
    // TokenReissueV1 {
    //     token_id: TokenId,
    //     amount_to_issue: Amount,
    // },
}

// TODO(NFT): Uncomment NftIssuanceV1
