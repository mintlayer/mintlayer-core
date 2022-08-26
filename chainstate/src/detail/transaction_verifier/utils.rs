use std::collections::BTreeMap;

use common::{
    chain::{
        tokens::{token_id, CoinOrTokenId, OutputValue, TokenData, TokensError},
        Transaction,
    },
    primitives::Amount,
};

use super::error::ConnectTransactionError;

pub fn insert_or_increase(
    total_amounts: &mut BTreeMap<CoinOrTokenId, Amount>,
    key: CoinOrTokenId,
    amount: Amount,
) -> Result<(), ConnectTransactionError> {
    match total_amounts.get_mut(&key) {
        Some(value) => {
            *value = (*value + amount).ok_or(ConnectTransactionError::TokensError(
                TokensError::CoinOrTokenOverflow,
            ))?;
        }
        None => {
            total_amounts.insert(key, amount);
        }
    }
    Ok(())
}

pub fn check_transferred_amount(
    inputs_total_map: &BTreeMap<CoinOrTokenId, Amount>,
    outputs_total_map: &BTreeMap<CoinOrTokenId, Amount>,
) -> Result<(), ConnectTransactionError> {
    for (coin_or_token_id, outputs_total) in outputs_total_map {
        // Is coin or token exist in inputs?
        let inputs_total = inputs_total_map
            .get(coin_or_token_id)
            .ok_or(ConnectTransactionError::MissingOutputOrSpent)?;

        // Does outputs exceed inputs?
        if outputs_total > inputs_total {
            return Err(ConnectTransactionError::AttemptToPrintMoney(
                *inputs_total,
                *outputs_total,
            ));
        }
    }
    Ok(())
}

pub fn filter_for_total_outputs(output_value: &OutputValue) -> Option<(CoinOrTokenId, &Amount)> {
    match output_value {
        OutputValue::Coin(amount) => Some((CoinOrTokenId::Coin, amount)),
        OutputValue::Token(token_data) => match token_data {
            TokenData::TokenTransferV1 { token_id, amount } => {
                Some((CoinOrTokenId::TokenId(*token_id), amount))
            }
            TokenData::TokenIssuanceV1 {
                token_ticker: _,
                amount_to_issue: _,
                number_of_decimals: _,
                metadata_uri: _,
            } => {
                // TODO: Might be it's not necessary at all?
                // if include_issuance {
                // ...
                // }
                None
            }
            TokenData::TokenBurnV1 {
                token_id,
                amount_to_burn,
            } => Some((CoinOrTokenId::TokenId(*token_id), amount_to_burn)),
        },
    }
}

pub fn filter_for_total_inputs(
    output_value: &OutputValue,
    tx: &Transaction,
) -> Result<(CoinOrTokenId, Amount), ConnectTransactionError> {
    Ok(match output_value {
        OutputValue::Coin(amount) => (CoinOrTokenId::Coin, *amount),
        OutputValue::Token(token_data) => match token_data {
            TokenData::TokenTransferV1 { token_id, amount } => {
                (CoinOrTokenId::TokenId(*token_id), *amount)
            }
            TokenData::TokenIssuanceV1 {
                token_ticker: _,
                amount_to_issue,
                number_of_decimals: _,
                metadata_uri: _,
            } => {
                let token_id = token_id(tx).ok_or(ConnectTransactionError::TokensError(
                    TokensError::TokenIdCantBeCalculated,
                ))?;
                (CoinOrTokenId::TokenId(token_id), *amount_to_issue)
            }
            TokenData::TokenBurnV1 {
                token_id: _,
                amount_to_burn: _,
            } => {
                /* Token have burned and can't be transferred */
                return Err(ConnectTransactionError::TokensError(
                    TokensError::AttemptToTransferBurnedTokens,
                ));
            }
        },
    })
}
