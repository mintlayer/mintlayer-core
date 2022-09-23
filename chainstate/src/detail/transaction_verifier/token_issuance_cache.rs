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
    txid_vs_tokenid: BTreeMap<Id<Transaction>, TokenId>,
}

impl TokenIssuanceCache {
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
            txid_vs_tokenid: BTreeMap::new(),
        }
    }

    #[cfg(test)]
    pub fn new_for_test(
        data: BTreeMap<TokenId, CachedTokensOperation>,
        txid_vs_tokenid: BTreeMap<Id<Transaction>, TokenId>,
    ) -> Self {
        Self {
            data,
            txid_vs_tokenid,
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
        self.insert_aux_data(token_id, TokenAuxiliaryData::new(tx.clone(), block_id))?;

        // TODO: this probably needs better modeling. Currently, we just want to know what the token id is for a given issuance tx id
        self.txid_vs_tokenid.insert(tx.get_id(), token_id);
        Ok(())
    }

    fn insert_aux_data(
        &mut self,
        token_id: TokenId,
        data: TokenAuxiliaryData,
    ) -> Result<(), TokensError> {
        match self.data.entry(token_id) {
            Entry::Occupied(_) => Err(TokensError::InvariantBrokenRegisterIssuanceWithDuplicateId(
                token_id,
            )),
            Entry::Vacant(e) => {
                e.insert(CachedTokensOperation::Write(data));
                Ok(())
            }
        }
    }

    fn write_undo_issuance(&mut self, tx: &Transaction) -> Result<(), TokensError> {
        let token_id = token_id(tx).ok_or(TokensError::TokenIdCantBeCalculated)?;
        self.remove_aux_data(token_id, tx.get_id())?;

        self.txid_vs_tokenid.insert(tx.get_id(), token_id);

        Ok(())
    }

    fn remove_aux_data(
        &mut self,
        token_id: TokenId,
        tx_id: Id<Transaction>,
    ) -> Result<(), TokensError> {
        match self.data.entry(token_id) {
            Entry::Occupied(mut e) => {
                e.insert(CachedTokensOperation::Erase(tx_id));
                Ok(())
            }
            Entry::Vacant(_) => Err(TokensError::InvariantBrokenUndoIssuanceOnNonexistentToken(
                token_id,
            )),
        }
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

    pub fn set_token_aux_data(
        &mut self,
        token_id: &TokenId,
        data: TokenAuxiliaryData,
    ) -> Result<(), TokensError> {
        self.insert_aux_data(*token_id, data)
    }

    pub fn del_token_aux_data(&mut self, token_id: &TokenId) -> Result<(), TokensError> {
        if let Some(op) = self.data.get(token_id) {
            let tx_id = match op {
                CachedTokensOperation::Write(data) => data.issuance_tx().get_id(),
                CachedTokensOperation::Read(data) => data.issuance_tx().get_id(),
                CachedTokensOperation::Erase(id) => *id,
            };
            self.remove_aux_data(*token_id, tx_id);
        }
        Ok(())
    }

    pub fn set_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
        token_id: &TokenId,
    ) -> Result<(), TokensError> {
        self.txid_vs_tokenid.insert(*issuance_tx_id, *token_id);
        Ok(())
    }

    pub fn del_token_id(&mut self, issuance_tx_id: &Id<Transaction>) -> Result<(), TokensError> {
        self.txid_vs_tokenid.remove(issuance_tx_id);
        Ok(())
    }

    pub fn data(&self) -> &BTreeMap<TokenId, CachedTokensOperation> {
        &self.data
    }

    pub fn txid_from_issuance(&self) -> &BTreeMap<Id<Transaction>, TokenId> {
        &self.txid_vs_tokenid
    }

    pub fn take(self) -> BTreeMap<TokenId, CachedTokensOperation> {
        self.data
    }
}

// TODO: write tests for operations
