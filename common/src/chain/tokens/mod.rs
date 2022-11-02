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

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum OutputValue {
    Coin(Amount),
    Token(Box<TokenData>),
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

impl From<TokenData> for OutputValue {
    fn from(d: TokenData) -> Self {
        Self::Token(Box::new(d))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct TokenTransfer {
    pub token_id: TokenId,
    pub amount: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct TokenIssuance {
    pub token_ticker: Vec<u8>,
    pub amount_to_issue: Amount,
    pub number_of_decimals: u8,
    pub metadata_uri: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum TokenData {
    /// TokenTransfer data to another user. If it is a token, then the token data must also be transferred to the recipient.
    #[codec(index = 1)]
    TokenTransfer(TokenTransfer),
    /// New token creation
    #[codec(index = 2)]
    TokenIssuance(Box<TokenIssuance>),
    // A new NFT creation
    #[codec(index = 3)]
    NftIssuance(Box<NftIssuance>),
    // TODO: These types will be implemented in the future PRs
    // // Increase amount of tokens
    // #[codec(index = 4)]
    // TokenReissueV1 {
    //     token_id: TokenId,
    //     amount_to_issue: Amount,
    // },
}

impl From<NftIssuance> for TokenData {
    fn from(d: NftIssuance) -> Self {
        Self::NftIssuance(Box::new(d))
    }
}

impl From<TokenIssuance> for TokenData {
    fn from(d: TokenIssuance) -> Self {
        Self::TokenIssuance(Box::new(d))
    }
}

impl From<TokenTransfer> for OutputValue {
    fn from(d: TokenTransfer) -> Self {
        TokenData::TokenTransfer(d).into()
    }
}

impl From<NftIssuance> for OutputValue {
    fn from(d: NftIssuance) -> Self {
        TokenData::NftIssuance(Box::new(d)).into()
    }
}

impl From<TokenIssuance> for OutputValue {
    fn from(d: TokenIssuance) -> Self {
        TokenData::TokenIssuance(Box::new(d)).into()
    }
}
