use std::collections::{btree_map::Entry, BTreeMap};

use common::{
    chain::{
        tokens::{is_tokens_issuance, token_id, TokenId, TokensError},
        Block, Transaction,
    },
    primitives::{Id, Idable},
};

use super::{cached_operation::CachedTokensOperation, error::ConnectTransactionError};

// Token registration saves the token id in the database with the transaction that issued it, and possible some additional auxiliary data;
// This helps in finding the relevant information of the token at any time in the future.
pub fn register_tokens_issuance(
    tokens_cache: &mut BTreeMap<TokenId, CachedTokensOperation>,
    block_id: Id<Block>,
    tx: &Transaction,
) -> Result<(), TokensError> {
    let token_id = token_id(tx).ok_or(TokensError::TokenIdCantBeCalculated)?;

    let _tokens_op = match tokens_cache.entry(token_id) {
        Entry::Occupied(_) => {
            return Err(TokensError::InvariantBrokenDuplicateTokenId(
                tx.get_id(),
                block_id,
            ));
        }
        Entry::Vacant(entry) => entry.insert(CachedTokensOperation::Write(tx.clone().into())),
    };
    Ok(())
}
pub fn unregister_token_issuance(
    tokens_cache: &mut BTreeMap<TokenId, CachedTokensOperation>,
    tx: &Transaction,
) -> Result<(), ConnectTransactionError> {
    let was_tokens_issued = tx.outputs().iter().any(|output| is_tokens_issuance(output.value()));
    if was_tokens_issued {
        let token_id = token_id(tx).ok_or(ConnectTransactionError::TokensError(
            TokensError::TokenIdCantBeCalculated,
        ))?;
        undo_issuance(tokens_cache, token_id)?;
    }
    Ok(())
}

fn undo_issuance(
    tokens_cache: &mut BTreeMap<TokenId, CachedTokensOperation>,
    token_id: TokenId,
) -> Result<(), TokensError> {
    match tokens_cache.entry(token_id) {
        Entry::Occupied(entry) => {
            let tokens_op = entry.into_mut();
            *tokens_op = CachedTokensOperation::Erase;
        }
        Entry::Vacant(_) => {
            return Err(TokensError::InvariantBrokenUndoIssuanceOnNonexistentToken(
                token_id,
            ))
        }
    }
    Ok(())
}
