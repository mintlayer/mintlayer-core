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

use std::num::NonZeroUsize;

use chainstate_storage::BlockchainStorageRead;
use chainstate_types::{BlockIndex, GenBlockIndex, Locator, PropertyQueryError};
use common::{
    chain::{
        block::{signed_block_header::SignedBlockHeader, BlockReward},
        output_value::RpcOutputValue,
        tokens::{
            NftIssuance, RPCFungibleTokenInfo, RPCIsTokenFrozen, RPCNonFungibleTokenInfo,
            RPCTokenInfo, TokenAuxiliaryData, TokenId,
        },
        AccountType, Block, GenBlock, OrderId, RpcOrderInfo, Transaction, TxOutput,
    },
    primitives::{Amount, BlockDistance, BlockHeight, Id, Idable},
};
use orders_accounting::{OrderData, OrdersAccountingStorageRead};
use tokens_accounting::TokensAccountingStorageRead;
use utils::ensure;

use super::{chainstateref, tx_verification_strategy::TransactionVerificationStrategy};

pub fn locator_tip_distances() -> impl Iterator<Item = BlockDistance> {
    itertools::iterate(0, |&i| std::cmp::max(1, i * 2)).map(BlockDistance::new)
}

pub struct ChainstateQuery<'a, S, V> {
    chainstate_ref: chainstateref::ChainstateRef<'a, S, V>,
}

impl<'a, S: BlockchainStorageRead, V: TransactionVerificationStrategy> ChainstateQuery<'a, S, V> {
    pub(crate) fn new(chainstate_ref: chainstateref::ChainstateRef<'a, S, V>) -> Self {
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
    ) -> Result<Option<SignedBlockHeader>, PropertyQueryError> {
        self.chainstate_ref.get_header_from_height(height)
    }

    pub fn get_block_header(
        &self,
        id: Id<Block>,
    ) -> Result<Option<SignedBlockHeader>, PropertyQueryError> {
        self.chainstate_ref.get_block_header(id)
    }

    pub fn get_block_id_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, PropertyQueryError> {
        self.chainstate_ref.get_block_id_by_height(height)
    }

    pub fn get_block(&self, id: Id<Block>) -> Result<Option<Block>, PropertyQueryError> {
        self.chainstate_ref.get_block(id)
    }

    pub fn get_existing_block(&self, id: Id<Block>) -> Result<Block, PropertyQueryError> {
        self.chainstate_ref.get_block(id)?.ok_or(PropertyQueryError::BlockNotFound(id))
    }

    pub fn get_mainchain_blocks(
        &self,
        mut from: BlockHeight,
        max_count: usize,
    ) -> Result<Vec<Block>, PropertyQueryError> {
        utils::ensure!(
            from != BlockHeight::zero(),
            PropertyQueryError::InvalidStartingBlockHeightForMainchainBlocks(from)
        );

        let mut res = Vec::new();
        for _ in 0..max_count {
            match self.get_block_id_from_height(&from)? {
                Some(get_block_id) => {
                    match get_block_id.classify(self.chainstate_ref.chain_config()) {
                        common::chain::GenBlockId::Genesis(_) => {
                            panic!("genesis block received at non-zero height {from}")
                        }
                        common::chain::GenBlockId::Block(block_id) => {
                            let block = self.get_block(block_id)?.unwrap_or_else(|| {
                                panic!("can't find block {block_id} at height {from}")
                            });
                            res.push(block);
                        }
                    }
                }
                None => break,
            }
            from = from.next_height();
        }

        Ok(res)
    }

    pub fn get_block_index_for_persisted_block(
        &self,
        id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError> {
        let index = self.chainstate_ref.get_block_index(id)?;
        Ok(index.and_then(|index| index.is_persisted().then_some(index)))
    }

    pub fn get_block_index_for_any_block(
        &self,
        id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError> {
        self.chainstate_ref.get_block_index(id)
    }

    pub fn get_gen_block_index_for_persisted_block(
        &self,
        id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
        let index = self.chainstate_ref.get_gen_block_index(id)?;
        Ok(index.and_then(|index| index.is_persisted().then_some(index)))
    }

    pub fn get_gen_block_index_for_any_block(
        &self,
        id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
        self.chainstate_ref.get_gen_block_index(id)
    }

    pub fn get_best_block_index(&self) -> Result<GenBlockIndex, PropertyQueryError> {
        self.chainstate_ref.get_best_block_index()
    }

    pub fn get_best_block_header(&self) -> Result<SignedBlockHeader, PropertyQueryError> {
        let best_block_index = self.chainstate_ref.get_best_block_index()?;
        match best_block_index {
            GenBlockIndex::Block(b) => Ok(b.block_header().clone()),
            GenBlockIndex::Genesis(_) => Err(PropertyQueryError::GenesisHeaderRequested),
        }
    }

    pub fn get_locator(&self) -> Result<Locator, PropertyQueryError> {
        let best_block_index = self.chainstate_ref.get_best_block_index()?;
        let height = best_block_index.block_height();
        self.get_locator_from_height(height)
    }

    pub fn get_locator_from_height(
        &self,
        height: BlockHeight,
    ) -> Result<Locator, PropertyQueryError> {
        let headers = locator_tip_distances()
            .map_while(|dist| height - dist)
            .map(|ht| self.chainstate_ref.get_block_id_by_height(&ht));

        itertools::process_results(headers, |iter| iter.flatten().collect::<Vec<_>>())
            .map(Locator::new)
    }

    pub fn get_block_ids_as_checkpoints(
        &self,
        start_height: BlockHeight,
        end_height: BlockHeight,
        step: NonZeroUsize,
    ) -> Result<Vec<(BlockHeight, Id<GenBlock>)>, PropertyQueryError> {
        ensure!(
            end_height >= start_height,
            PropertyQueryError::InvalidBlockHeightRange {
                start: start_height,
                end: end_height
            }
        );

        let max_height = self.chainstate_ref.get_best_block_index()?.block_height();

        if start_height > max_height || start_height == end_height {
            return Ok(Vec::new());
        }

        let start_height = std::cmp::min(start_height, max_height);
        let end_height = std::cmp::min(end_height, max_height.next_height());

        let iter =
            (start_height.into_int()..end_height.into_int())
                .step_by(step.into())
                .map(|height| {
                    let height = BlockHeight::new(height);
                    Ok((
                        height,
                        self.chainstate_ref.get_existing_block_id_by_height(&height)?,
                    ))
                });

        itertools::process_results(iter, |iter| iter.collect::<Vec<_>>())
    }

    pub fn is_block_in_main_chain(&self, id: &Id<GenBlock>) -> Result<bool, PropertyQueryError> {
        self.chainstate_ref.is_block_in_main_chain(id)
    }

    pub fn get_min_height_with_allowed_reorg(&self) -> Result<BlockHeight, PropertyQueryError> {
        self.chainstate_ref.get_min_height_with_allowed_reorg()
    }

    pub fn get_block_height_in_main_chain(
        &self,
        id: &Id<GenBlock>,
    ) -> Result<Option<BlockHeight>, PropertyQueryError> {
        self.chainstate_ref.get_block_height_in_main_chain(id)
    }

    fn get_mainchain_headers_higher_than(
        &self,
        height: BlockHeight,
        header_count_limit: usize,
    ) -> Result<Vec<SignedBlockHeader>, PropertyQueryError> {
        let header_count_limit = BlockDistance::new(
            header_count_limit.try_into().expect("Unreasonable header count limit"),
        );

        // get headers until either the best block or header limit is reached
        let best_height = self.chainstate_ref.get_best_block_index()?.block_height();

        let limit = std::cmp::min(
            (height + header_count_limit).expect("BlockHeight limit reached"),
            best_height,
        );

        let headers = itertools::iterate(height.next_height(), |iter| iter.next_height())
            .take_while(|height| height <= &limit)
            .map(|height| self.chainstate_ref.get_header_from_height(&height));
        itertools::process_results(headers, |iter| iter.flatten().collect::<Vec<_>>())
    }

    pub fn get_mainchain_headers_by_locator(
        &self,
        locator: &Locator,
        header_count_limit: usize,
    ) -> Result<Vec<SignedBlockHeader>, PropertyQueryError> {
        // use genesis block if no common ancestor with better block height is found
        let mut best_height = BlockHeight::new(0);

        for block_id in locator.iter() {
            if let Some(block_index) = self.chainstate_ref.get_gen_block_index(block_id)? {
                if self.chainstate_ref.is_block_in_main_chain(block_id)? {
                    best_height = block_index.block_height();
                    break;
                }
            }
        }

        self.get_mainchain_headers_higher_than(best_height, header_count_limit)
    }

    pub fn get_mainchain_headers_since_latest_fork_point(
        &self,
        block_ids: &[Id<GenBlock>],
        header_count_limit: usize,
    ) -> Result<Vec<SignedBlockHeader>, PropertyQueryError> {
        if block_ids.is_empty() {
            return Ok(Vec::new());
        }

        let latest_fork_point_height = {
            let mut best_height = BlockHeight::zero();

            for block_id in block_ids {
                let block_index = self.chainstate_ref.get_existing_gen_block_index(block_id)?;
                let fork_point_block_index =
                    self.chainstate_ref.last_common_ancestor_in_main_chain(&block_index)?;

                best_height = std::cmp::max(best_height, fork_point_block_index.block_height());
            }

            best_height
        };

        self.get_mainchain_headers_higher_than(latest_fork_point_height, header_count_limit)
    }

    pub fn get_token_info_for_rpc(
        &self,
        token_id: TokenId,
    ) -> Result<Option<RPCTokenInfo>, PropertyQueryError> {
        if let Some(token_data) = self.chainstate_ref.get_token_data(&token_id)? {
            let circulating_supply =
                self.chainstate_ref.get_circulating_supply(&token_id)?.unwrap_or(Amount::ZERO);

            match token_data {
                tokens_accounting::TokenData::FungibleToken(token_data) => {
                    let rpc_issuance = RPCTokenInfo::new_fungible(RPCFungibleTokenInfo::new(
                        token_id,
                        token_data.token_ticker().to_owned(),
                        token_data.number_of_decimals(),
                        token_data.metadata_uri().to_owned(),
                        circulating_supply,
                        (*token_data.total_supply()).into(),
                        token_data.is_locked(),
                        RPCIsTokenFrozen::new(token_data.frozen_state()),
                        token_data.authority().clone(),
                    ));
                    Ok(Some(rpc_issuance))
                }
            }
        } else {
            let token_aux_data = match self.get_token_aux_data(&token_id)? {
                Some(data) => data,
                None => return Ok(None),
            };

            Ok(token_aux_data
                .issuance_tx()
                .outputs()
                .iter()
                // find tokens
                .find_map(|output| match output {
                    TxOutput::Transfer(_, _)
                    | TxOutput::LockThenTransfer(_, _, _)
                    | TxOutput::Burn(_)
                    | TxOutput::CreateStakePool(_, _)
                    | TxOutput::ProduceBlockFromStake(_, _)
                    | TxOutput::CreateDelegationId(_, _)
                    | TxOutput::DelegateStaking(_, _)
                    | TxOutput::DataDeposit(_)
                    | TxOutput::Htlc(_, _)
                    | TxOutput::CreateOrder(_) => None,
                    TxOutput::IssueNft(_, issuance, _) => match issuance.as_ref() {
                        NftIssuance::V0(nft) => {
                            Some(RPCTokenInfo::new_nonfungible(RPCNonFungibleTokenInfo::new(
                                token_id,
                                token_aux_data.issuance_tx().get_id(),
                                token_aux_data.issuance_block_id(),
                                &nft.metadata,
                            )))
                        }
                    },
                    // Should be handled by the token data branch
                    TxOutput::IssueFungibleToken(_) => None,
                }))
        }
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

    pub fn get_mainchain_blocks_list(&self) -> Result<Vec<Id<Block>>, PropertyQueryError> {
        self.chainstate_ref.get_mainchain_blocks_list()
    }

    pub fn get_block_id_tree_as_list(&self) -> Result<Vec<Id<Block>>, PropertyQueryError> {
        self.chainstate_ref.get_block_id_tree_as_list()
    }

    pub fn get_token_data(
        &self,
        id: &TokenId,
    ) -> Result<Option<tokens_accounting::TokenData>, PropertyQueryError> {
        self.chainstate_ref.get_token_data(id).map_err(PropertyQueryError::from)
    }

    pub fn get_token_circulating_supply(
        &self,
        id: &TokenId,
    ) -> Result<Option<Amount>, PropertyQueryError> {
        self.chainstate_ref.get_circulating_supply(id).map_err(PropertyQueryError::from)
    }

    pub fn get_order_data(&self, id: &OrderId) -> Result<Option<OrderData>, PropertyQueryError> {
        self.chainstate_ref.get_order_data(id).map_err(PropertyQueryError::from)
    }

    pub fn get_order_ask_balance(
        &self,
        id: &OrderId,
    ) -> Result<Option<Amount>, PropertyQueryError> {
        self.chainstate_ref.get_ask_balance(id).map_err(PropertyQueryError::from)
    }

    pub fn get_order_give_balance(
        &self,
        id: &OrderId,
    ) -> Result<Option<Amount>, PropertyQueryError> {
        self.chainstate_ref.get_give_balance(id).map_err(PropertyQueryError::from)
    }

    pub fn get_order_info_for_rpc(
        &self,
        order_id: OrderId,
    ) -> Result<Option<RpcOrderInfo>, PropertyQueryError> {
        self.get_order_data(&order_id)?
            .map(|order_data| {
                let ask_balance = self
                    .get_order_ask_balance(&order_id)?
                    .ok_or(PropertyQueryError::OrderBalanceNotFound(order_id))?;
                let give_balance = self
                    .get_order_give_balance(&order_id)?
                    .ok_or(PropertyQueryError::OrderBalanceNotFound(order_id))?;

                let nonce =
                    self.chainstate_ref.get_account_nonce_count(AccountType::Order(order_id))?;

                let initially_asked = RpcOutputValue::from_output_value(order_data.ask())
                    .ok_or(PropertyQueryError::UnsupportedTokenV0InOrder(order_id))?;
                let initially_given = RpcOutputValue::from_output_value(order_data.give())
                    .ok_or(PropertyQueryError::UnsupportedTokenV0InOrder(order_id))?;

                let info = RpcOrderInfo {
                    conclude_key: order_data.conclude_key().clone(),
                    initially_asked,
                    initially_given,
                    give_balance,
                    ask_balance,
                    nonce,
                };

                Ok(info)
            })
            .transpose()
    }
}
