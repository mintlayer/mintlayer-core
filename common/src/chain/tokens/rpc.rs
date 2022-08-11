use serialization::Decode;
use serialization::Encode;

// use crate::primitives::VersionTag;
use crate::{
    chain::{Block, Transaction},
    primitives::{Amount, Id},
};

use super::TokenId;

#[derive(Debug, Clone, Encode, Decode, serde::Serialize, serde::Deserialize)]
pub struct RPCTokenInfoV1 {
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

impl RPCTokenInfoV1 {
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
