use common::{
    chain::{
        config::{TOKEN_MAX_DEC_COUNT, TOKEN_MAX_TICKER_LEN, TOKEN_MAX_URI_LEN},
        tokens::{TokenData, TokenId},
        Block, Transaction,
    },
    primitives::{Amount, Id, Idable},
};
use utils::ensure;

use crate::detail::TokensError;

pub fn check_token_transfer_data(
    block_id: Id<Block>,
    tx: &Transaction,
    _token_id: &TokenId,
    amount: &Amount,
) -> Result<(), TokensError> {
    // Check amount
    ensure!(
        amount > &Amount::from_atoms(0),
        TokensError::TransferZeroTokens(tx.get_id(), block_id)
    );

    Ok(())
}

pub fn check_token_burn_data(
    tx: &Transaction,
    block_id: &Id<Block>,
    _burn_token_id: &TokenId,
    amount_to_burn: &Amount,
) -> Result<(), TokensError> {
    // Check amount
    ensure!(
        amount_to_burn != &Amount::from_atoms(0),
        TokensError::BurnZeroTokens(tx.get_id(), *block_id)
    );
    Ok(())
}

pub fn check_token_issuance_data(
    token_ticker: &Vec<u8>,
    amount_to_issue: &Amount,
    number_of_decimals: &u8,
    metadata_uri: &Vec<u8>,
    tx_id: Id<Transaction>,
    block_id: Id<Block>,
) -> Result<(), TokensError> {
    //TODO: Shall we have check for unique token name?

    // Check token name
    if token_ticker.len() > TOKEN_MAX_TICKER_LEN
        || token_ticker.is_empty()
        || !String::from_utf8_lossy(token_ticker).is_ascii()
    {
        return Err(TokensError::IssueErrorIncorrectTicker(tx_id, block_id));
    }

    // Check amount
    if amount_to_issue == &Amount::from_atoms(0) {
        return Err(TokensError::IssueErrorIncorrectAmount(tx_id, block_id));
    }

    // Check decimals
    if number_of_decimals > &TOKEN_MAX_DEC_COUNT {
        return Err(TokensError::IssueErrorTooManyDecimals(tx_id, block_id));
    }

    // Check URI
    if metadata_uri.len() > TOKEN_MAX_URI_LEN || !String::from_utf8_lossy(metadata_uri).is_ascii() {
        return Err(TokensError::IssueErrorIncorrectMetadataURI(tx_id, block_id));
    }
    Ok(())
}

pub fn check_tokens_data(
    token: &TokenData,
    tx: &Transaction,
    block: &Block,
) -> Result<(), TokensError> {
    match token {
        TokenData::TokenTransferV1 { token_id, amount } => {
            check_token_transfer_data(block.get_id(), tx, token_id, amount)?;
        }
        TokenData::TokenIssuanceV1 {
            token_ticker,
            amount_to_issue,
            number_of_decimals,
            metadata_uri,
        } => {
            check_token_issuance_data(
                token_ticker,
                amount_to_issue,
                number_of_decimals,
                metadata_uri,
                tx.get_id(),
                block.get_id(),
            )?;
        }
        TokenData::TokenBurnV1 {
            token_id,
            amount_to_burn,
        } => {
            check_token_burn_data(tx, &block.get_id(), token_id, amount_to_burn)?;
        }
    }
    Ok(())
}
