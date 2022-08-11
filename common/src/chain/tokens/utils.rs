use super::{OutputValue, TokenData, TokenId};
use crate::{chain::Transaction, primitives::id::hash_encoded};

pub fn token_id(tx: &Transaction) -> Option<TokenId> {
    Some(hash_encoded(tx.inputs().get(0)?))
}

pub fn get_tokens_issuance_count(tx: &Transaction) -> usize {
    tx.outputs()
        .iter()
        .filter_map(|output| match output.value() {
            OutputValue::Coin(_) => None,
            OutputValue::Token(asset) => Some(asset),
        })
        .fold(0, |accum, asset| match asset {
            TokenData::TokenTransferV1 {
                token_id: _,
                amount: _,
            } => accum,
            TokenData::TokenIssuanceV1 {
                token_ticker: _,
                amount_to_issue: _,
                number_of_decimals: _,
                metadata_uri: _,
            } => accum + 1,
            TokenData::TokenBurnV1 {
                token_id: _,
                amount_to_burn: _,
            } => accum,
        })
}
