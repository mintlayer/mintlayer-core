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

use serialization::Decode;
use serialization::Encode;

// use crate::primitives::VersionTag;
use crate::{
    chain::{Block, Transaction},
    primitives::{Amount, Id},
};

use super::TokenId;

#[derive(Debug, Clone, Encode, Decode, serde::Serialize, serde::Deserialize)]
pub struct RPCTokenInfo {
    // TODO: Should we use here VersionTag?
    pub version: u32,
    pub token_id: TokenId,
    // TODO: Should we return in RPC the owner info
    // pub owner: u8,
    pub creation_tx_id: Id<Transaction>,
    pub creation_block_id: Id<Block>,
    pub token_ticker: Vec<u8>,
    pub amount_to_issue: Amount,
    pub number_of_decimals: u8,
    pub metadata_uri: Vec<u8>,
}

impl RPCTokenInfo {
    pub fn new(
        token_id: TokenId,
        // owner: u8,
        creation_tx_id: Id<Transaction>,
        creation_block_id: Id<Block>,
        token_ticker: Vec<u8>,
        amount_to_issue: Amount,
        number_of_decimals: u8,
        metadata_uri: Vec<u8>,
    ) -> Self {
        Self {
            version: 1,
            token_id,
            // owner,
            creation_tx_id,
            creation_block_id,
            token_ticker,
            amount_to_issue,
            number_of_decimals,
            metadata_uri,
        }
    }
}
