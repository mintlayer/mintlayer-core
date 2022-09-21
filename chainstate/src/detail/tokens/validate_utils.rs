use common::{
    chain::{Block, ChainConfig, Transaction},
    primitives::Id,
};
use utils::ensure;

use crate::TokensError;

pub fn check_token_name(
    chain_config: &ChainConfig,
    token_name: &[u8],
    tx_id: Id<Transaction>,
    source_block_id: Id<Block>,
) -> Result<(), TokensError> {
    if token_name.len() > chain_config.token_max_name_len() || token_name.is_empty() {
        return Err(TokensError::IssueErrorInvalidTickerLength(
            tx_id,
            source_block_id,
        ));
    }
    Ok(())
}

pub fn check_token_ticker(
    chain_config: &ChainConfig,
    token_ticker: &[u8],
    tx_id: Id<Transaction>,
    source_block_id: Id<Block>,
) -> Result<(), TokensError> {
    if token_ticker.len() > chain_config.token_max_ticker_len() || token_ticker.is_empty() {
        return Err(TokensError::IssueErrorInvalidTickerLength(
            tx_id,
            source_block_id,
        ));
    }
    Ok(())
}

pub fn check_token_description(
    chain_config: &ChainConfig,
    token_ticker: &[u8],
    tx_id: Id<Transaction>,
    source_block_id: Id<Block>,
) -> Result<(), TokensError> {
    if token_ticker.len() > chain_config.token_max_ticker_len() || token_ticker.is_empty() {
        return Err(TokensError::IssueErrorInvalidTickerLength(
            tx_id,
            source_block_id,
        ));
    }
    Ok(())
}

pub fn check_alphanumeric(
    str: &[u8],
    tx_id: Id<Transaction>,
    source_block_id: Id<Block>,
) -> Result<(), TokensError> {
    let is_alphanumeric = String::from_utf8(str.to_vec())
        .map_err(|_| TokensError::IssueErrorTickerHasNoneAlphaNumericChar(tx_id, source_block_id))?
        .chars()
        .all(char::is_alphanumeric);

    ensure!(
        is_alphanumeric,
        TokensError::IssueErrorTickerHasNoneAlphaNumericChar(tx_id, source_block_id)
    );
    Ok(())
}

pub fn check_url(
    chain_config: &ChainConfig,
    url: &[u8],
    tx_id: Id<Transaction>,
    source_block_id: Id<Block>,
) -> Result<(), TokensError> {
    let is_validated = String::from_utf8(url.to_vec())
        // FIXME(nft_issuance): Make more appropriate error
        .map_err(|_| TokensError::IssueErrorIncorrectMetadataURI(tx_id, source_block_id))?
        .chars()
        // TODO: this is probably an invalid way to validate URLs. Find the proper way to do this in rust.
        .all(|ch| ch.is_alphanumeric() || ch.is_ascii_punctuation() || ch.is_ascii_control());

    ensure!(
        is_validated && url.len() <= chain_config.token_max_uri_len(),
        // FIXME(nft_issuance): Make more appropriate error
        TokensError::IssueErrorIncorrectMetadataURI(tx_id, source_block_id)
    );
    Ok(())
}

pub fn check_media_hash(_hash: &Vec<u8>) -> Result<(), TokensError> {
    unimplemented!()
}
