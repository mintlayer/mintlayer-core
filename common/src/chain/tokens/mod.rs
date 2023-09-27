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

use crypto::random::{CryptoRng, Rng};
use serialization::{Decode, DecodeAll, Encode};
use typename::TypeName;

#[derive(Eq, PartialEq, TypeName)]
pub enum Token {}

pub type TokenId = Id<Token>;
pub type NftDataHash = Vec<u8>;
use crate::{
    address::{traits::Addressable, AddressError},
    primitives::{Amount, Id, H256},
};

impl TokenId {
    pub fn random_using<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self::new(H256::random_using(rng))
    }

    pub const fn zero() -> Self {
        Self::new(H256::zero())
    }
}

impl Addressable for TokenId {
    type Error = AddressError;

    fn address_prefix(&self, chain_config: &ChainConfig) -> &str {
        chain_config.token_id_address_prefix()
    }

    fn encode_to_bytes_for_address(&self) -> Vec<u8> {
        self.encode()
    }

    fn decode_from_bytes_from_address<T: AsRef<[u8]>>(address_bytes: T) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Self::decode_all(&mut address_bytes.as_ref())
            .map_err(|e| AddressError::DecodingError(e.to_string()))
    }

    fn json_wrapper_prefix() -> &'static str {
        "HexifiedTokenId"
    }
}

mod nft;
mod rpc;
mod tokens_utils;

pub use nft::*;
pub use rpc::*;
pub use tokens_utils::*;

use super::{Block, ChainConfig, Transaction};

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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, serde::Serialize)]
pub struct TokenTransfer {
    pub token_id: TokenId,
    pub amount: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, serde::Serialize)]
pub struct TokenIssuance {
    pub token_ticker: Vec<u8>,
    pub amount_to_issue: Amount,
    pub number_of_decimals: u8,
    pub metadata_uri: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, serde::Serialize)]
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
