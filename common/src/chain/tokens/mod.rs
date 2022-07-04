use parity_scale_codec::{Decode, Encode};

pub type TokenId = Vec<u8>;
pub type NftDataHash = Vec<u8>;

use crate::primitives::Amount;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum OutputValue {
    Coin(Amount),
    Asset(AssetData),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum AssetData {
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
    // // Burning a token or NFT
    // #[codec(index = 3)]
    // TokenBurnV1 {
    //     token_id: TokenId,
    //     amount_to_burn: Amount,
    // },
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
