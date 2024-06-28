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

use super::{Block, Destination, Transaction};
use crate::primitives::{Amount, Id};
use serialization::{Decode, Encode};

mod issuance;
mod nft;
mod rpc;
mod token_id;
mod tokens_utils;

pub use issuance::*;
pub use nft::*;
pub use rpc::*;
pub use token_id::TokenId;
pub use tokens_utils::*;

pub fn is_rfc3986_valid_symbol(ch: char) -> bool {
    // RFC 3986 alphabet taken from https://www.rfc-editor.org/rfc/rfc3986#section-2.1
    "%:/?#[]@!$&\'()*+,;=-._~".chars().any(|rfc1738_ch| ch == rfc1738_ch)
}

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

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct TokenTransfer {
    pub token_id: TokenId,
    pub amount: Amount,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct TokenIssuanceV0 {
    pub token_ticker: Vec<u8>,
    pub amount_to_issue: Amount,
    pub number_of_decimals: u8,
    pub metadata_uri: Vec<u8>,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum TokenData {
    /// TokenTransfer data to another user. If it is a token, then the token data must also be transferred to the recipient.
    #[codec(index = 1)]
    TokenTransfer(TokenTransfer),
    /// New token creation
    #[codec(index = 2)]
    TokenIssuance(Box<TokenIssuanceV0>),
    // A new NFT creation
    #[codec(index = 3)]
    NftIssuance(Box<NftIssuanceV0>),
}

impl From<NftIssuanceV0> for TokenData {
    fn from(d: NftIssuanceV0) -> Self {
        Self::NftIssuance(Box::new(d))
    }
}

impl From<TokenIssuanceV0> for TokenData {
    fn from(d: TokenIssuanceV0) -> Self {
        Self::TokenIssuance(Box::new(d))
    }
}
