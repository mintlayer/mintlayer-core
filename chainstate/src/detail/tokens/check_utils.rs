use common::chain::ChainConfig;
use utils::ensure;

use crate::TokensError;

use super::error::CheckTokensError;

pub fn check_token_text_length(text: &[u8], max_len: usize) -> Result<(), CheckTokensError> {
    if text.len() > max_len || text.is_empty() {
        return Err(CheckTokensError::InvalidTextLength);
    }

    Ok(())
}

pub fn check_is_text_alphanumeric(str: &[u8]) -> Result<(), CheckTokensError> {
    let is_alphanumeric = String::from_utf8(str.to_vec())
        .map_err(|_| CheckTokensError::InvalidCharancter)?
        .chars()
        .all(char::is_alphanumeric);

    ensure!(is_alphanumeric, CheckTokensError::InvalidCharancter);
    Ok(())
}

fn is_rfc1738_valid_symbol(ch: char) -> bool {
    // RFC 1738 alphabet
    String::from(":._-~!/?#[]@$&\'()*+,;=")
        .chars()
        .any(|rfc1738_ch| ch == rfc1738_ch)
}

pub fn check_uri(chain_config: &ChainConfig, uri: &[u8]) -> Result<(), CheckTokensError> {
    let is_validated = String::from_utf8(uri.to_vec())
        .map_err(|_| CheckTokensError::InvalidURI)?
        .chars()
        // TODO: this is probably an invalid way to validate URLs. Find the proper way to do this in rust.
        .all(|ch| ch.is_alphanumeric() || is_rfc1738_valid_symbol(ch));

    ensure!(
        is_validated && (uri.len() <= chain_config.token_max_uri_len()) && !uri.is_empty(),
        CheckTokensError::InvalidURI
    );
    Ok(())
}

pub fn check_media_hash(_hash: &[u8]) -> Result<(), TokensError> {
    // FIXME(nft_issuance): Research: What kinds of Hash might be here? Can we check correctness of the hash.
    Ok(())
}
