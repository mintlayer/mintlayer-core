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
    pub public_key: PublicKey,
}

impl From<PublicKey> for TokenCreator {
    fn from(public_key: PublicKey) -> Self {
        Self { public_key }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct Metadata {
    pub creator: TokenCreator,
    pub name: Vec<u8>,
    pub description: Vec<u8>,
    pub ticker: Vec<u8>,
    pub icon_uri: Option<Vec<u8>>,
    pub additional_metadata_uri: Option<Vec<u8>>,
    pub media_uri: Option<Vec<u8>>,
    pub media_hash: Vec<u8>,
    // FIXME(nft_issuance): Check how it is should work
    // pub issuead_at: Option<u64>,
    // pub expired_at: Option<u64>,
    // pub valid_since: Option<u64>,
    // pub refund_period: Option<u64>,
}

pub struct Payout {
    pub payout: HashMap<Destination, Amount>,
}

pub struct Royalty {
    pub royalties: HashMap<Destination, Percentage>,
}

pub type Percentage = u8;
