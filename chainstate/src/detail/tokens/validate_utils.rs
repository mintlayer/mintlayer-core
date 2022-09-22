use common::{
    chain::{Block, ChainConfig, Transaction},
    primitives::Id,
};
use utils::ensure;

use crate::TokensError;

pub fn check_token_name(
    chain_config: &ChainConfig,
    name: &[u8],
    tx_id: Id<Transaction>,
    source_block_id: Id<Block>,
) -> Result<(), TokensError> {
    // Check length
    if name.len() > chain_config.token_max_name_len() || name.is_empty() {
        return Err(TokensError::IssueErrorInvalidNameLength(
            tx_id,
            source_block_id,
        ));
    }

    Ok(())
}

pub fn check_token_ticker(
    chain_config: &ChainConfig,
    ticker: &[u8],
    tx_id: Id<Transaction>,
    source_block_id: Id<Block>,
) -> Result<(), TokensError> {
    if ticker.len() > chain_config.token_max_ticker_len() || ticker.is_empty() {
        return Err(TokensError::IssueErrorInvalidTickerLength(
            tx_id,
            source_block_id,
        ));
    }
    Ok(())
}

pub fn check_token_description(
    chain_config: &ChainConfig,
    description: &[u8],
    tx_id: Id<Transaction>,
    source_block_id: Id<Block>,
) -> Result<(), TokensError> {
    if description.len() > chain_config.token_max_description_len() || description.is_empty() {
        return Err(TokensError::IssueErrorInvalidDescriptionLength(
            tx_id,
            source_block_id,
        ));
    }
    Ok(())
}

// FIXME(nft_issuance): These functions below are equal, make one general function
pub fn check_is_ticker_alphanumeric(
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

pub fn check_is_name_alphanumeric(
    str: &[u8],
    tx_id: Id<Transaction>,
    source_block_id: Id<Block>,
) -> Result<(), TokensError> {
    let is_alphanumeric = String::from_utf8(str.to_vec())
        .map_err(|_| TokensError::IssueErrorNameHasNoneAlphaNumericChar(tx_id, source_block_id))?
        .chars()
        .all(char::is_alphanumeric);

    ensure!(
        is_alphanumeric,
        TokensError::IssueErrorNameHasNoneAlphaNumericChar(tx_id, source_block_id)
    );
    Ok(())
}

pub fn check_is_description_alphanumeric(
    str: &[u8],
    tx_id: Id<Transaction>,
    source_block_id: Id<Block>,
) -> Result<(), TokensError> {
    let is_alphanumeric = String::from_utf8(str.to_vec())
        .map_err(|_| {
            TokensError::IssueErrorDescriptionHasNoneAlphaNumericChar(tx_id, source_block_id)
        })?
        .chars()
        .all(char::is_alphanumeric);

    ensure!(
        is_alphanumeric,
        TokensError::IssueErrorDescriptionHasNoneAlphaNumericChar(tx_id, source_block_id)
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
    // FIXME(nft_issuance): Research: What kinds of Hash might be here? Can we check correctness of the hash.
    Ok(())
}
