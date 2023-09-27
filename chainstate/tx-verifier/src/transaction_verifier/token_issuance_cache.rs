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
        tokens::{
            get_tokens_issuance_v0_count, token_id, TokenAuxiliaryData, TokenId,
            TokenIssuanceVersion,
        },
        Block, ChainConfig, RequiredConsensus, Transaction,
    },
    primitives::{Id, Idable, H256},
};

use super::{
    error::{ConnectTransactionError, TokensError},
    CachedOperation, TransactionSourceForConnect,
};

pub type CachedAuxDataOp = CachedOperation<TokenAuxiliaryData>;
pub type CachedTokenIndexOp = CachedOperation<TokenId>;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum CoinOrTokenId {
    Coin,
    TokenId(TokenId),
}

#[derive(Debug, Eq, PartialEq)]
pub struct ConsumedTokenIssuanceCache {
    pub data: BTreeMap<TokenId, CachedAuxDataOp>,
    pub txid_vs_tokenid: BTreeMap<Id<Transaction>, CachedTokenIndexOp>,
}

pub struct TokenIssuanceCache {
    data: BTreeMap<TokenId, CachedAuxDataOp>,
    txid_vs_tokenid: BTreeMap<Id<Transaction>, CachedTokenIndexOp>,
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
        data: BTreeMap<TokenId, CachedAuxDataOp>,
        txid_vs_tokenid: BTreeMap<Id<Transaction>, CachedTokenIndexOp>,
    ) -> Self {
        Self {
            data,
            txid_vs_tokenid,
        }
    }

    // Token registration saves the token id in the database with the transaction that issued it, and possibly some additional auxiliary data;
    // This helps in finding the relevant information of the token at any time in the future.
    pub fn register<E>(
        &mut self,
        chain_config: &ChainConfig,
        block_id: Option<Id<Block>>,
        tx: &Transaction,
        tx_source: &TransactionSourceForConnect,
        token_data_getter: impl Fn(&TokenId) -> Result<Option<TokenAuxiliaryData>, E>,
    ) -> Result<(), ConnectTransactionError>
    where
        ConnectTransactionError: From<E>,
    {
        let was_token_issued = get_tokens_issuance_v0_count(tx.outputs()) > 0;

        if was_token_issued {
            // Check that only v0 tokens were issued
            let consensus_status =
                chain_config.net_upgrade().consensus_status(tx_source.expected_block_height());
            let token_version = match consensus_status {
                RequiredConsensus::IgnoreConsensus => None,
                RequiredConsensus::PoW(_) => {
                    Some(chain_config.get_proof_of_work_config().token_issuance_version())
                }
                RequiredConsensus::PoS(pos_status) => {
                    Some(pos_status.get_chain_config().token_issuance_version())
                }
            };

            if let Some(token_version) = token_version {
                match token_version {
                    TokenIssuanceVersion::V0 => { /* do nothing */ }
                    TokenIssuanceVersion::V1 => {
                        return Err(ConnectTransactionError::TokensError(
                            TokensError::UnsupportedTokenIssuanceVersion(
                                tx.get_id(),
                                TokenIssuanceVersion::V1,
                            ),
                        ));
                    }
                    _ => unreachable!(),
                };
            }

            self.precache_token_issuance(token_data_getter, tx)?;

            self.write_issuance(&block_id.unwrap_or_else(|| H256::zero().into()), tx)?;
        }
        Ok(())
    }

    pub fn unregister<E>(
        &mut self,
        tx: &Transaction,
        token_data_getter: impl Fn(&TokenId) -> Result<Option<TokenAuxiliaryData>, E>,
    ) -> Result<(), ConnectTransactionError>
    where
        ConnectTransactionError: From<E>,
    {
        let was_token_issued = get_tokens_issuance_v0_count(tx.outputs()) > 0;

        if was_token_issued {
            self.precache_token_issuance(token_data_getter, tx)?;

            self.write_undo_issuance(tx)?;
        }
        Ok(())
    }

    fn write_issuance(
        &mut self,
        block_id: &Id<Block>,
        tx: &Transaction,
    ) -> Result<(), TokensError> {
        let token_id = token_id(tx).ok_or(TokensError::TokenIdCantBeCalculated)?;
        let aux_data = TokenAuxiliaryData::new(tx.clone(), *block_id);
        self.insert_aux_data(token_id, CachedAuxDataOp::Write(aux_data))?;

        // TODO: this probably needs better modeling. Currently, we just want to know what the token id is for a given issuance tx id
        self.txid_vs_tokenid.insert(tx.get_id(), CachedTokenIndexOp::Write(token_id));
        Ok(())
    }

    fn insert_aux_data(
        &mut self,
        token_id: TokenId,
        new_op: CachedAuxDataOp,
    ) -> Result<(), TokensError> {
        match self.data.entry(token_id) {
            Entry::Occupied(mut entry) => match entry.get() {
                CachedOperation::Write(_) | CachedOperation::Read(_) => Err(
                    TokensError::InvariantBrokenRegisterIssuanceWithDuplicateId(token_id),
                ),
                CachedOperation::Erase => {
                    entry.insert(new_op);
                    Ok(())
                }
            },
            Entry::Vacant(e) => {
                e.insert(new_op);
                Ok(())
            }
        }
    }

    fn write_undo_issuance(&mut self, tx: &Transaction) -> Result<(), TokensError> {
        let token_id = token_id(tx).ok_or(TokensError::TokenIdCantBeCalculated)?;
        match self.data.entry(token_id) {
            Entry::Occupied(mut e) => {
                e.insert(CachedAuxDataOp::Erase);
            }
            Entry::Vacant(_) => {
                return Err(TokensError::InvariantBrokenUndoIssuanceOnNonexistentToken(
                    token_id,
                ))
            }
        }
        self.del_token_id(&tx.get_id())?;
        Ok(())
    }

    fn precache_token_issuance<E>(
        &mut self,
        token_data_getter: impl Fn(&TokenId) -> Result<Option<TokenAuxiliaryData>, E>,
        tx: &Transaction,
    ) -> Result<(), ConnectTransactionError>
    where
        ConnectTransactionError: From<E>,
    {
        let has_token_issuance = get_tokens_issuance_v0_count(tx.outputs()) > 0;

        if has_token_issuance {
            let token_id = token_id(tx).ok_or(TokensError::TokenIdCantBeCalculated)?;
            match self.data.entry(token_id) {
                Entry::Vacant(e) => {
                    let current_token_data = token_data_getter(&token_id)?;
                    if let Some(el) = current_token_data {
                        e.insert(CachedAuxDataOp::Read(el));
                    }
                }
                Entry::Occupied(_) => {
                    return Err(ConnectTransactionError::TokensError(
                        TokensError::InvariantBrokenRegisterIssuanceWithDuplicateId(token_id),
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
        self.insert_aux_data(*token_id, CachedAuxDataOp::Write(data))
    }

    pub fn del_token_aux_data(&mut self, token_id: &TokenId) -> Result<(), TokensError> {
        self.insert_aux_data(*token_id, CachedAuxDataOp::Erase)
    }

    pub fn set_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
        token_id: &TokenId,
    ) -> Result<(), TokensError> {
        self.txid_vs_tokenid
            .insert(*issuance_tx_id, CachedTokenIndexOp::Write(*token_id));
        Ok(())
    }

    pub fn del_token_id(&mut self, issuance_tx_id: &Id<Transaction>) -> Result<(), TokensError> {
        self.txid_vs_tokenid.insert(*issuance_tx_id, CachedTokenIndexOp::Erase);
        Ok(())
    }

    pub fn data(&self) -> &BTreeMap<TokenId, CachedAuxDataOp> {
        &self.data
    }

    pub fn txid_from_issuance(&self) -> &BTreeMap<Id<Transaction>, CachedTokenIndexOp> {
        &self.txid_vs_tokenid
    }

    pub fn consume(self) -> ConsumedTokenIssuanceCache {
        ConsumedTokenIssuanceCache {
            data: self.data,
            txid_vs_tokenid: self.txid_vs_tokenid,
        }
    }
}

// TODO: write tests for operations
