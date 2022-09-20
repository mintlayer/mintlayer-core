use serialization::{Decode, Encode};
use std::collections::HashMap;

use crypto::key::PublicKey;

use crate::{chain::Destination, primitives::Amount};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct NftIssuanceV1 {
    pub metadata: Metadata,
    // pub payout: Payout, /// ???? Multisig contract with amount enforcement
    // pub royalty: Royalty,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct TokenCreator {
    pub pubkey: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
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
