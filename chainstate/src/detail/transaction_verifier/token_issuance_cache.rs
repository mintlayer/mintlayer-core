// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::{btree_map::Entry, BTreeMap};

use common::{
    chain::{
        tokens::{is_tokens_issuance, token_id, TokenAuxiliaryData, TokenId},
        Block, Transaction,
    },
    primitives::{Id, Idable},
};

use super::error::TokensError;

pub enum CachedTokensOperation {
    Write(TokenAuxiliaryData),
    Read(TokenAuxiliaryData),
    Erase(Id<Transaction>),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum CoinOrTokenId {
    Coin,
    TokenId(TokenId),
}

pub struct TokenIssuanceCache {
    data: BTreeMap<TokenId, CachedTokensOperation>,
}

impl TokenIssuanceCache {
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }

    // Token registration saves the token id in the database with the transaction that issued it, and possibly some additional auxiliary data;
    // This helps in finding the relevant information of the token at any time in the future.
    pub fn register(&mut self, block_id: Id<Block>, tx: &Transaction) -> Result<(), TokensError> {
        let was_token_issued = tx.outputs().iter().any(|output| is_tokens_issuance(output.value()));
        if was_token_issued {
            self.write_issuance(block_id, tx)?;
        }
        Ok(())
    }
    pub fn unregister(&mut self, tx: &Transaction) -> Result<(), TokensError> {
        let was_tokens_issued =
            tx.outputs().iter().any(|output| is_tokens_issuance(output.value()));

        if was_tokens_issued {
            self.write_undo_issuance(tx)?;
        }
        Ok(())
    }

    fn write_issuance(&mut self, block_id: Id<Block>, tx: &Transaction) -> Result<(), TokensError> {
        let token_id = token_id(tx).ok_or(TokensError::TokenIdCantBeCalculated)?;
        match self.data.entry(token_id) {
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

    fn write_undo_issuance(&mut self, tx: &Transaction) -> Result<(), TokensError> {
        let token_id = token_id(tx).ok_or(TokensError::TokenIdCantBeCalculated)?;
        match self.data.entry(token_id) {
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

    pub fn precache_token_issuance<
        F: Fn(&TokenId) -> Result<Option<TokenAuxiliaryData>, TokensError>,
    >(
        &mut self,
        token_data_getter: F,
        tx: &Transaction,
    ) -> Result<(), TokensError> {
        let has_token_issuance =
            tx.outputs().iter().any(|output| is_tokens_issuance(output.value()));
        if has_token_issuance {
            let token_id = token_id(tx).ok_or(TokensError::TokenIdCantBeCalculated)?;
            match self.data.entry(token_id) {
                Entry::Vacant(e) => {
                    let current_token_data = token_data_getter(&token_id)?;
                    if let Some(el) = current_token_data {
                        e.insert(CachedTokensOperation::Read(el));
                    }
                }
                Entry::Occupied(_) => {
                    return Err(TokensError::InvariantBrokenRegisterIssuanceWithDuplicateId(
                        token_id,
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn take(self) -> BTreeMap<TokenId, CachedTokensOperation> {
        self.data
    }
}

// TODO: write tests for operations
