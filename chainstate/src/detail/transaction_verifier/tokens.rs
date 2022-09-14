use std::collections::{btree_map::Entry, BTreeMap};

use common::{
    chain::{
        tokens::{is_tokens_issuance, token_id, TokenAuxiliaryData, TokenId, TokensError},
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
        write_issuance(tokens_cache, block_id, tx)?;
    }
    Ok(())
}
pub fn unregister_token_issuance(
    tokens_cache: &mut BTreeMap<TokenId, CachedTokensOperation>,
    tx: &Transaction,
) -> Result<(), TokensError> {
    let was_tokens_issued = tx.outputs().iter().any(|output| is_tokens_issuance(output.value()));

    if was_tokens_issued {
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
        Entry::Occupied(_) => {
            return Err(TokensError::InvariantBrokenRegisterIssuanceWithDuplicateId(
                token_id,
            ))
        }
        Entry::Vacant(e) => {
            e.insert(CachedTokensOperation::Write(TokenAuxiliaryData::new(
                tx.clone(),
                block_id,
            )));
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
        Entry::Occupied(mut e) => {
            e.insert(CachedTokensOperation::Erase(tx.get_id()));
        }
        Entry::Vacant(_) => {
            return Err(TokensError::InvariantBrokenUndoIssuanceOnNonexistentToken(
                token_id,
            ))
        }
    }
    Ok(())
}
