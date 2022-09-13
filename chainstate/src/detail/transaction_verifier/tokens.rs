use std::collections::{btree_map::Entry, BTreeMap};

use common::{
    chain::{
        tokens::{
            is_tokens_issuance, token_id, OutputValue, TokenAuxiliaryData, TokenData, TokenId,
            TokensError,
        },
        Block, Transaction,
    },
    primitives::{Id, Idable},
};

use super::cached_operation::CachedTokensOperation;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum CoinOrTokenId {
    Coin,
    TokenId(TokenId),
}

// TODO: get rid of these mut map references parameters and use self-contained objects for testability

// Token registration saves the token id in the database with the transaction that issued it, and possibly some additional auxiliary data;
// This helps in finding the relevant information of the token at any time in the future.
pub fn register_tokens_issuance(
    tokens_cache: &mut BTreeMap<TokenId, CachedTokensOperation>,
    block_id: Id<Block>,
    tx: &Transaction,
) -> Result<(), TokensError> {
    let was_token_issued = tx.outputs().iter().any(|output| is_tokens_issuance(output.value()));
    if was_token_issued {
        precache_issuance(tokens_cache, tx, block_id)?;
        write_issuance(tokens_cache, block_id, tx)?;
    }
    Ok(())
}
pub fn unregister_token_issuance(
    tokens_cache: &mut BTreeMap<TokenId, CachedTokensOperation>,
    tx: &Transaction,
    block_id: Id<Block>,
) -> Result<(), TokensError> {
    let was_tokens_issued = tx.outputs().iter().any(|output| is_tokens_issuance(output.value()));

    if was_tokens_issued {
        precache_issuance(tokens_cache, tx, block_id)?;
        undo_issuance(tokens_cache, tx)?;
    }
    Ok(())
}

fn write_issuance(
    tokens_cache: &mut BTreeMap<TokenId, CachedTokensOperation>,
    block_id: Id<Block>,
    tx: &Transaction,
) -> Result<(), TokensError> {
    let token_id = token_id(tx).ok_or(TokensError::TokenIdCantBeCalculated)?;
    match tokens_cache.entry(token_id) {
        Entry::Occupied(entry) => {
            let tokens_op = entry.into_mut();
            *tokens_op =
                CachedTokensOperation::Write(TokenAuxiliaryData::new(tx.clone(), block_id));
        }
        Entry::Vacant(_) => {
            return Err(TokensError::InvariantBrokenRegisterIssuanceOnNonexistentToken(token_id))
        }
    }
    Ok(())
}

fn undo_issuance(
    tokens_cache: &mut BTreeMap<TokenId, CachedTokensOperation>,
    tx: &Transaction,
) -> Result<(), TokensError> {
    let token_id = token_id(tx).ok_or(TokensError::TokenIdCantBeCalculated)?;
    match tokens_cache.entry(token_id) {
        Entry::Occupied(entry) => {
            let tokens_op = entry.into_mut();
            *tokens_op = CachedTokensOperation::Erase(tx.get_id());
        }
        Entry::Vacant(_) => {
            return Err(TokensError::InvariantBrokenUndoIssuanceOnNonexistentToken(
                token_id,
            ))
        }
    }
    Ok(())
}

fn precache_issuance(
    tokens_cache: &mut BTreeMap<TokenId, CachedTokensOperation>,
    tx: &Transaction,
    block_id: Id<Block>,
) -> Result<(), TokensError> {
    tx.outputs()
        .iter()
        .filter_map(|output| match output.value() {
            OutputValue::Coin(_) => None,
            OutputValue::Token(token_data) => Some(token_data),
        })
        .try_for_each(|token_data| try_to_cache_issuance(tokens_cache, tx, token_data, block_id))
}

fn try_to_cache_issuance(
    tokens_cache: &mut BTreeMap<TokenId, CachedTokensOperation>,
    tx: &Transaction,
    token_data: &TokenData,
    block_id: Id<Block>,
) -> Result<(), TokensError> {
    match token_data {
        TokenData::TokenIssuanceV1 {
            token_ticker: _,
            amount_to_issue: _,
            number_of_decimals: _,
            metadata_uri: _,
        } => {
            let token_id = token_id(tx).ok_or(TokensError::TokenIdCantBeCalculated)?;
            let _tokens_op = match tokens_cache.entry(token_id) {
                Entry::Occupied(_) => {
                    return Err(TokensError::InvariantBrokenDuplicateTokenId(
                        tx.get_id(),
                        block_id,
                    ));
                }
                Entry::Vacant(entry) => entry.insert(CachedTokensOperation::Read(
                    TokenAuxiliaryData::new(tx.clone(), block_id),
                )),
            };
            Ok(())
        }
        TokenData::TokenTransferV1 {
            token_id: _,
            amount: _,
        }
        | TokenData::TokenBurnV1 {
            token_id: _,
            amount_to_burn: _,
        } => Ok(()),
    }
}
