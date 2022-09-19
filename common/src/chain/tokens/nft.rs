use std::collections::HashMap;

use crypto::key::PublicKey;

use crate::{chain::Destination, primitives::Amount};

use super::TokenId;

// Storages
// 1. Map TokenId vs Option<TokenAuxiliaryData>
// 2. Map Id<Transaction> vs Option<TokenId>
// 3. Map TokenId vs Operator (PubKey or PubKeyHash) - operator can use delegated tokens without take ownership

// RPC
//
//

// Questions
// BalanceOf - should return MultiTokenId and amount of Tokens
//

pub enum TokenDataV2 {
    TokenTransferV1(TokenTransferV1),
    TokenIssuanceV1(TokenIssuanceV1),
    TokenBurnV1(TokenBurnV1),
    NftIssuanceV1(NftIssuanceV1),
    //  Multi Tokens
    // MultiTokenTransferV1(Vec<MultiTokenTransferV1>),
    // MultiTokenIssuanceV1(Vec<MultiTokenIssuanceV1>),
    MultiTokenIssuanceV1(Vec<MultiTokenIssuanceV1>),
    // Approve
    // SetApproveV1(token id, operator)
    // AllowanceV1(AllowanceV1)
}

pub enum MultiTokenIssuanceV1 {
    Fungible(/* id, amount ... */),
    NoneFungible(/* metadata, ... */), // amount???
}

pub struct TokenTransferV1 {
    pub token_id: TokenId,
    pub amount: Amount,
}

pub struct TokenIssuanceV1 {
    pub token_ticker: Vec<u8>,
    pub amount_to_issue: Amount,
    pub number_of_decimals: u8,
    pub metadata_uri: Vec<u8>,
}

pub struct TokenBurnV1 {
    pub token_id: TokenId,
    pub amount_to_burn: Amount,
}

pub struct NftIssuanceV1 {
    pub metadata: Metadata,
    // pub payout: Payout, /// ???? Multisig contract with amount enforcement
    // pub royalty: Royalty,
}

pub struct TokenCreator {
    pub pubkey: PublicKey,
}

pub struct Metadata {
    pub creator: TokenCreator,
    pub name: Vec<u8>,
    pub description: Vec<u8>,
    pub ticker: Vec<u8>,
    pub icon_url: Option<Vec<u8>>,
    pub additional_metadata_url: Option<Vec<u8>>,
    pub media_url: Option<Vec<u8>>,
    pub media_hash: Vec<u8>,
    pub issuead_at: Option<u64>,
    pub expired_at: Option<u64>,
    pub valid_since: Option<u64>,
    pub refund_period: Option<u64>,
}

pub struct Payout {
    pub payout: HashMap<Destination, Amount>,
}

pub struct Royalty {
    pub royalties: HashMap<Destination, Percentage>,
}

pub type Percentage = u8;
