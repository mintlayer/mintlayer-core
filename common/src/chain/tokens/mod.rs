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
use crate::primitives::{Amount, H256};

mod rpc;
mod utils;

pub use rpc::*;
pub use utils::*;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum OutputValue {
    Coin(Amount),
    Token(TokenData),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum TokenData {
    // TokenTransfer data to another user. If it is a token, then the token data must also be transferred to the recipient.
    #[codec(index = 1)]
    TokenTransferV1 { token_id: TokenId, amount: Amount },
    // A new token creation
    #[codec(index = 2)]
    TokenIssuanceV1 {
        token_ticker: Vec<u8>,
        amount_to_issue: Amount,
        // Should be not more than 18 numbers
        number_of_decimals: u8,
        metadata_uri: Vec<u8>,
    },
    // Burning a token or NFT
    #[codec(index = 3)]
    TokenBurnV1 {
        token_id: TokenId,
        amount_to_burn: Amount,
    },
    // // Increase amount of tokens
    // #[codec(index = 4)]
    // TokenReissueV1 {
    //     token_id: TokenId,
    //     amount_to_issue: Amount,
    // },
    // // A new NFT creation
    // #[codec(index = 5)]
    // NftIssuanceV1 {
    //     data_hash: NftDataHash,
    //     metadata_uri: Vec<u8>,
    // },
}
