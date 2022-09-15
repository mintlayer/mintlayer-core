// Copyright (c) 2021-2022 RBB S.r.l
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

use chainstate_storage::BlockchainStorageRead;
use chainstate_types::{BlockIndex, GenBlockIndex, Locator, PropertyQueryError};
use common::{
    chain::{
        block::{BlockHeader, BlockReward},
        tokens::{OutputValue, RPCTokenInfo, TokenAuxiliaryData, TokenData, TokenId},
        Block, GenBlock, OutPointSourceId, Transaction, TxMainChainIndex,
    },
    primitives::{BlockDistance, BlockHeight, Id, Idable},
};

use super::{chainstateref, orphan_blocks::OrphanBlocks, HEADER_LIMIT};

pub fn locator_tip_distances() -> impl Iterator<Item = BlockDistance> {
    itertools::iterate(0, |&i| std::cmp::max(1, i * 2)).map(BlockDistance::new)
}

pub struct ChainstateQuery<'a, S, O> {
    chainstate_ref: chainstateref::ChainstateRef<'a, S, O>,
}

impl<'a, S: BlockchainStorageRead, O: OrphanBlocks> ChainstateQuery<'a, S, O> {
    pub(crate) fn new(chainstate_ref: chainstateref::ChainstateRef<'a, S, O>) -> Self {
        Self { chainstate_ref }
    }

    pub fn get_best_block_id(&self) -> Result<Id<GenBlock>, PropertyQueryError> {
        self.chainstate_ref.get_best_block_id()
    }

    #[allow(dead_code)]
    pub fn get_block_reward(
        &self,
        block_index: &BlockIndex,
    ) -> Result<Option<BlockReward>, PropertyQueryError> {
        self.chainstate_ref.get_block_reward(block_index)
    }

    #[allow(dead_code)]
    pub fn get_header_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<BlockHeader>, PropertyQueryError> {
        self.chainstate_ref.get_header_from_height(height)
    }

    pub fn get_block_id_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, PropertyQueryError> {
        self.chainstate_ref
            .get_block_id_by_height(height)
            .map(|res| res.map(Into::into))
    }

    pub fn get_block(&self, id: Id<Block>) -> Result<Option<Block>, PropertyQueryError> {
        self.chainstate_ref.get_block(id)
    }

    pub fn get_block_index(
        &self,
        id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError> {
        self.chainstate_ref.get_block_index(id)
    }

    pub fn get_gen_block_index(
        &self,
        id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
        self.chainstate_ref.get_gen_block_index(id)
    }

    pub fn get_best_block_index(&self) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
        self.chainstate_ref.get_best_block_index()
    }

    pub fn get_locator(&self) -> Result<Locator, PropertyQueryError> {
        let best_block_index = self
            .chainstate_ref
            .get_best_block_index()?
            .ok_or(PropertyQueryError::BestBlockIndexNotFound)?;
        let height = best_block_index.block_height();

        let headers = locator_tip_distances()
            .map_while(|dist| height - dist)
            .map(|ht| self.chainstate_ref.get_block_id_by_height(&ht));

        itertools::process_results(headers, |iter| iter.flatten().collect::<Vec<_>>())
            .map(Locator::new)
    }

    pub fn get_block_height_in_main_chain(
        &self,
        id: &Id<GenBlock>,
    ) -> Result<Option<BlockHeight>, PropertyQueryError> {
        self.chainstate_ref.get_block_height_in_main_chain(id)
    }

    pub fn get_headers(&self, locator: Locator) -> Result<Vec<BlockHeader>, PropertyQueryError> {
        // use genesis block if no common ancestor with better block height is found
        let mut best = BlockHeight::new(0);

        for block_id in locator.iter() {
            if let Some(block_index) = self.chainstate_ref.get_gen_block_index(block_id)? {
                if self.chainstate_ref.is_block_in_main_chain(block_id)? {
                    best = block_index.block_height();
                    break;
                }
            }
        }

        // get headers until either the best block or header limit is reached
        let best_height = self
            .chainstate_ref
            .get_best_block_index()?
            .expect("best block's height to exist")
            .block_height();

        let limit = std::cmp::min(
            (best + HEADER_LIMIT).expect("BlockHeight limit reached"),
            best_height,
        );

        let headers = itertools::iterate(best.next_height(), |iter| iter.next_height())
            .take_while(|height| height <= &limit)
            .map(|height| self.chainstate_ref.get_header_from_height(&height));
        itertools::process_results(headers, |iter| iter.flatten().collect::<Vec<_>>())
    }

    pub fn filter_already_existing_blocks(
        &self,
        headers: Vec<BlockHeader>,
    ) -> Result<Vec<BlockHeader>, PropertyQueryError> {
        let first_block = headers.get(0).ok_or(PropertyQueryError::InvalidInputEmpty)?;
        let config = &self.chainstate_ref.chain_config();
        // verify that the first block attaches to our chain
        if let Some(id) = first_block.prev_block_id().classify(config).chain_block_id() {
            utils::ensure!(
                self.get_block_index(&id)?.is_some(),
                PropertyQueryError::BlockNotFound(id)
            );
        }

        let res = headers
            .into_iter()
            .skip_while(|header| {
                self.get_block_index(&header.get_id()).expect("Database failure").is_some()
            })
            .collect::<Vec<_>>();

        Ok(res)
    }

    pub fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<TxMainChainIndex>, PropertyQueryError> {
        self.chainstate_ref.get_mainchain_tx_index(tx_id)
    }

    pub fn get_token_info_for_rpc(
        &self,
        token_id: TokenId,
    ) -> Result<Option<RPCTokenInfo>, PropertyQueryError> {
        let token_aux_data = self.get_token_aux_data(&token_id)?;
        let token_aux_data = match token_aux_data {
            Some(data) => data,
            None => return Ok(None),
        };

        Ok(token_aux_data
            .issuance_tx()
            .outputs()
            .iter()
            // Filter tokens
            .filter_map(|output| match output.value() {
                OutputValue::Coin(_) => None,
                OutputValue::Token(token_data) => Some(token_data),
            })
            // Find issuance data and return RPCTokenInfo
            .find_map(|token_data| match token_data {
                TokenData::TokenIssuanceV1 {
                    token_ticker,
                    amount_to_issue,
                    number_of_decimals,
                    metadata_uri,
                } => Some(RPCTokenInfo::new(
                    token_id,
                    token_aux_data.issuance_tx().get_id(),
                    token_aux_data.issuance_block_id(),
                    token_ticker.clone(),
                    *amount_to_issue,
                    *number_of_decimals,
                    metadata_uri.clone(),
                )),
                TokenData::TokenTransferV1 {
                    token_id: _,
                    amount: _,
                }
                | TokenData::TokenBurnV1 {
                    token_id: _,
                    amount_to_burn: _,
                } => None,
            }))
    }

    pub fn get_token_aux_data(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<TokenAuxiliaryData>, PropertyQueryError> {
        self.chainstate_ref.get_token_aux_data(token_id)
    }

    pub fn get_token_id_from_issuance_tx(
        &self,
        tx_id: &Id<Transaction>,
    ) -> Result<Option<TokenId>, PropertyQueryError> {
        self.chainstate_ref.get_token_id(tx_id)
    }
}
