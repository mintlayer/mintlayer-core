// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    consensus_validator::TransactionIndexHandle, median_time::calculate_median_time_past,
    time_getter::TimeGetterFn, TokensError,
};
use chainstate_storage::{BlockchainStorageRead, BlockchainStorageWrite, TransactionRw};
use chainstate_types::{block_index::BlockIndex, height_skip::get_skip_height};
use common::{
    chain::{
        block::{calculate_tx_merkle_root, calculate_witness_merkle_root, Block, BlockHeader},
        calculate_tx_index_from_block,
        config::{
            TOKEN_MAX_DEC_COUNT, TOKEN_MAX_TICKER_LEN, TOKEN_MAX_URI_LEN, TOKEN_MIN_ISSUANCE_FEE,
        },
        tokens::{token_id, AssetData, OutputValue, TokenId},
        ChainConfig, OutPoint, OutPointSourceId, Transaction,
    },
    primitives::{Amount, BlockDistance, BlockHeight, Id, Idable, H256},
    Uint256,
};
use logging::log;
use utils::ensure;

use crate::{BlockError, BlockSource};

use super::{
    consensus_validator::{self, BlockIndexHandle},
    orphan_blocks::{OrphanBlocks, OrphanBlocksMut},
    spend_cache::{BlockTransactableRef, CachedInputs},
    BlockSizeError, CheckBlockError, CheckBlockTransactionsError, OrphanCheckError,
    PropertyQueryError,
};

pub(crate) struct ChainstateRef<'a, S, O> {
    chain_config: &'a ChainConfig,
    db_tx: S,
    orphan_blocks: O,
    time_getter: &'a TimeGetterFn,
}

impl<'a, S: BlockchainStorageRead, O: OrphanBlocks> BlockIndexHandle for ChainstateRef<'a, S, O> {
    fn get_block_index(
        &self,
        block_index: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError> {
        self.get_block_index(block_index)
    }
    fn get_ancestor(
        &self,
        block_index: &BlockIndex,
        ancestor_height: BlockHeight,
    ) -> Result<BlockIndex, PropertyQueryError> {
        self.get_ancestor(block_index, ancestor_height)
    }
}

impl<'a, S: BlockchainStorageRead, O: OrphanBlocks> TransactionIndexHandle
    for ChainstateRef<'a, S, O>
{
    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<common::chain::TxMainChainIndex>, PropertyQueryError> {
        self.get_mainchain_tx_index(tx_id)
    }

    fn get_mainchain_tx_by_position(
        &self,
        tx_index: &common::chain::TxMainChainPosition,
    ) -> Result<Option<common::chain::Transaction>, PropertyQueryError> {
        self.get_mainchain_tx_by_position(tx_index)
    }
}

impl<'a, S: TransactionRw<Error = chainstate_storage::Error>, O> ChainstateRef<'a, S, O> {
    pub fn commit_db_tx(self) -> chainstate_storage::Result<()> {
        self.db_tx.commit()
    }
}

impl<'a, S: BlockchainStorageRead, O: OrphanBlocks> ChainstateRef<'a, S, O> {
    pub fn new_rw(
        chain_config: &'a ChainConfig,
        db_tx: S,
        orphan_blocks: O,
        time_getter: &'a TimeGetterFn,
    ) -> ChainstateRef<'a, S, O> {
        ChainstateRef {
            chain_config,
            db_tx,
            orphan_blocks,
            time_getter,
        }
    }

    pub fn new_ro(
        chain_config: &'a ChainConfig,
        db_tx: S,
        orphan_blocks: O,
        time_getter: &'a TimeGetterFn,
    ) -> ChainstateRef<'a, S, O> {
        ChainstateRef {
            chain_config,
            db_tx,
            orphan_blocks,
            time_getter,
        }
    }

    pub fn current_time(&self) -> std::time::Duration {
        (self.time_getter)()
    }

    pub fn get_best_block_id(&self) -> Result<Option<Id<Block>>, PropertyQueryError> {
        self.db_tx.get_best_block_id().map_err(PropertyQueryError::from)
    }

    pub fn get_block_index(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError> {
        log::trace!("Loading block index of id: {}", block_id);
        self.db_tx.get_block_index(block_id).map_err(PropertyQueryError::from)
    }

    pub fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<common::chain::TxMainChainIndex>, PropertyQueryError> {
        log::trace!("Loading transaction index of id: {:?}", tx_id);
        self.db_tx.get_mainchain_tx_index(tx_id).map_err(PropertyQueryError::from)
    }

    fn get_mainchain_tx_by_position(
        &self,
        tx_index: &common::chain::TxMainChainPosition,
    ) -> Result<Option<common::chain::Transaction>, PropertyQueryError> {
        log::trace!("Loading transaction by pos: {:?}", tx_index);
        self.db_tx
            .get_mainchain_tx_by_position(tx_index)
            .map_err(PropertyQueryError::from)
    }

    pub fn get_block_id_by_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<Block>>, PropertyQueryError> {
        self.db_tx.get_block_id_by_height(height).map_err(PropertyQueryError::from)
    }

    pub fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, PropertyQueryError> {
        self.db_tx.get_block(block_id).map_err(PropertyQueryError::from)
    }

    pub fn is_block_in_main_chain(
        &self,
        block_index: &BlockIndex,
    ) -> Result<bool, PropertyQueryError> {
        let height = block_index.block_height();
        let id_at_height =
            self.db_tx.get_block_id_by_height(&height).map_err(PropertyQueryError::from)?;
        match id_at_height {
            Some(id) => Ok(id == *block_index.block_id()),
            None => Ok(false),
        }
    }

    /// Allow to read from storage the previous block and return itself BlockIndex
    fn get_previous_block_index(
        &self,
        block_index: &BlockIndex,
    ) -> Result<BlockIndex, PropertyQueryError> {
        let prev_block_id = block_index.prev_block_id().as_ref().ok_or_else(|| {
            PropertyQueryError::BlockIndexHasNoPrevBlock(block_index.block_id().clone())
        })?;
        self.db_tx
            .get_block_index(prev_block_id)?
            .ok_or_else(|| PropertyQueryError::PrevBlockIndexNotFound(prev_block_id.clone()))
    }

    pub fn get_ancestor(
        &self,
        block_index: &BlockIndex,
        target_height: BlockHeight,
    ) -> Result<BlockIndex, PropertyQueryError> {
        if target_height > block_index.block_height() {
            return Err(PropertyQueryError::InvalidAncestorHeight {
                block_height: block_index.block_height(),
                ancestor_height: target_height,
            });
        }

        let step_to_prev_block = |block_index_walk: &mut BlockIndex,
                                  height_walk: &mut BlockHeight|
         -> Result<(), PropertyQueryError> {
            *block_index_walk = self.get_previous_block_index(block_index_walk)?;
            *height_walk = (*height_walk - BlockDistance::from(1))
                .expect("height_walk is greater than height");
            Ok(())
        };

        let mut height_walk = block_index.block_height();
        let mut block_index_walk = block_index.clone();
        while height_walk > target_height {
            let height_walk_prev = (height_walk - BlockDistance::new(1))
                .expect("Can never fail because prev is zero at worst");

            let height_skip = get_skip_height(height_walk);
            let height_skip_prev = get_skip_height(height_walk_prev);
            match block_index_walk.some_ancestor() {
                Some(ancestor) => {
                    // prepare the booleans for the check
                    let at_target = height_skip == target_height;
                    let still_not_there = height_skip > target_height;
                    let too_close = height_skip_prev.next_height().next_height() < height_skip;
                    let prev_too_close = height_skip_prev >= target_height;

                    if at_target || (still_not_there && !(too_close && prev_too_close)) {
                        block_index_walk = self
                            .get_block_index(ancestor)?
                            .expect("Block index of ancestor must exist, since id exists");
                        height_walk = height_skip;
                    } else {
                        step_to_prev_block(&mut block_index_walk, &mut height_walk)?;
                    }
                }
                None => step_to_prev_block(&mut block_index_walk, &mut height_walk)?,
            };
        }
        Ok(block_index_walk)
    }

    #[allow(unused)]
    pub fn last_common_ancestor(
        &self,
        first_block_index: &BlockIndex,
        second_block_index: &BlockIndex,
    ) -> Result<BlockIndex, PropertyQueryError> {
        let mut first_block_index = first_block_index.clone();
        let mut second_block_index = second_block_index.clone();
        match first_block_index.block_height().cmp(&second_block_index.block_height()) {
            std::cmp::Ordering::Greater => {
                first_block_index =
                    self.get_ancestor(&first_block_index, second_block_index.block_height())?;
            }
            std::cmp::Ordering::Less => {
                second_block_index =
                    self.get_ancestor(&second_block_index, first_block_index.block_height())?;
            }
            std::cmp::Ordering::Equal => {}
        }

        while first_block_index.block_id() != second_block_index.block_id()
            && !first_block_index.is_genesis(self.chain_config)
            && !second_block_index.is_genesis(self.chain_config)
        {
            first_block_index = self.get_previous_block_index(&first_block_index)?;
            second_block_index = self.get_previous_block_index(&second_block_index)?;
        }
        assert_eq!(first_block_index.block_id(), second_block_index.block_id());
        Ok(first_block_index)
    }

    pub fn get_best_block_index(&self) -> Result<Option<BlockIndex>, PropertyQueryError> {
        let best_block_id = match self.get_best_block_id()? {
            Some(id) => id,
            None => return Ok(None),
        };
        self.get_block_index(&best_block_id)
    }

    pub fn get_header_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<BlockHeader>, PropertyQueryError> {
        let id = self
            .get_block_id_by_height(height)?
            .ok_or(PropertyQueryError::BlockForHeightNotFound(*height))?;
        Ok(self.get_block_index(&id)?.map(|block_index| block_index.into_block_header()))
    }

    pub fn get_block_height_in_main_chain(
        &self,
        id: &Id<Block>,
    ) -> Result<Option<BlockHeight>, PropertyQueryError> {
        let block_index = self.get_block_index(id)?;
        let block_index =
            block_index.ok_or_else(|| PropertyQueryError::BlockNotFound(id.clone()))?;
        if block_index.block_id() == id {
            Ok(Some(block_index.block_height()))
        } else {
            Ok(None)
        }
    }

    // Get indexes for a new longest chain
    fn get_new_chain(
        &self,
        new_tip_block_index: &BlockIndex,
    ) -> Result<Vec<BlockIndex>, PropertyQueryError> {
        let mut result = Vec::new();
        let mut block_index = new_tip_block_index.clone();
        while !self.is_block_in_main_chain(&block_index)? {
            result.push(block_index.clone());
            block_index = self.get_previous_block_index(&block_index)?;
        }
        result.reverse();
        debug_assert!(!result.is_empty()); // there has to always be at least one new block
        Ok(result)
    }

    fn check_block_index(&self, block_index: &BlockIndex) -> Result<(), BlockError> {
        // BlockIndex is already known or block exists
        if self.db_tx.get_block_index(block_index.block_id())?.is_some() {
            return Err(BlockError::BlockAlreadyExists(
                block_index.block_id().clone(),
            ));
        }
        // TODO: Will be expanded
        Ok(())
    }

    fn check_block_detail(&self, block: &Block) -> Result<(), CheckBlockError> {
        // MerkleTree root
        let merkle_tree_root = block.merkle_root();
        calculate_tx_merkle_root(block.transactions()).map_or(
            Err(CheckBlockError::MerkleRootMismatch),
            |merkle_tree| {
                ensure!(
                    merkle_tree_root == merkle_tree,
                    CheckBlockError::MerkleRootMismatch
                );
                Ok(())
            },
        )?;

        // Witness merkle root
        let witness_merkle_root = block.witness_merkle_root();
        calculate_witness_merkle_root(block.transactions()).map_or(
            Err(CheckBlockError::WitnessMerkleRootMismatch),
            |witness_merkle| {
                ensure!(
                    witness_merkle_root == witness_merkle,
                    CheckBlockError::WitnessMerkleRootMismatch,
                );
                Ok(())
            },
        )?;

        match &block.prev_block_id() {
            Some(prev_block_id) => {
                let median_time_past = calculate_median_time_past(self, prev_block_id);
                ensure!(
                    block.timestamp() >= median_time_past,
                    CheckBlockError::BlockTimeOrderInvalid,
                );

                let max_future_offset = self.chain_config.max_future_block_time_offset();
                let current_time = self.current_time();
                let block_timestamp = block.timestamp();
                ensure!(
                    block_timestamp.as_duration_since_epoch() <= current_time + *max_future_offset,
                    CheckBlockError::BlockFromTheFuture,
                );
            }
            None => {
                // This is only for genesis, AND should never come from a peer
                ensure!(
                    block.is_genesis(self.chain_config),
                    CheckBlockError::InvalidBlockNoPrevBlock,
                );
            }
        }

        self.check_transactions(block)
            .map_err(CheckBlockError::CheckTransactionFailed)?;

        self.check_block_size(block).map_err(CheckBlockError::BlockSizeError)?;

        Ok(())
    }

    fn check_block_size(&self, block: &Block) -> Result<(), BlockSizeError> {
        let block_size = block.block_size();

        ensure!(
            block_size.size_from_header() <= self.chain_config.max_block_header_size(),
            BlockSizeError::Header(
                block_size.size_from_header(),
                self.chain_config.max_block_header_size()
            )
        );

        ensure!(
            block_size.size_from_txs() <= self.chain_config.max_block_size_from_txs(),
            BlockSizeError::SizeOfTxs(
                block_size.size_from_txs(),
                self.chain_config.max_block_size_from_txs()
            )
        );

        ensure!(
            block_size.size_from_smart_contracts()
                <= self.chain_config.max_block_size_from_smart_contracts(),
            BlockSizeError::SizeOfSmartContracts(
                block_size.size_from_smart_contracts(),
                self.chain_config.max_block_size_from_smart_contracts()
            )
        );

        Ok(())
    }

    fn check_duplicate_inputs(&self, block: &Block) -> Result<(), CheckBlockTransactionsError> {
        // check for duplicate inputs (see CVE-2018-17144)
        let mut block_inputs = BTreeSet::new();
        for tx in block.transactions() {
            let mut tx_inputs = BTreeSet::new();
            for input in tx.inputs() {
                if !block_inputs.insert(input.outpoint()) {
                    return Err(CheckBlockTransactionsError::DuplicateInputInBlock(
                        block.get_id(),
                    ));
                }
                if !tx_inputs.insert(input.outpoint()) {
                    return Err(CheckBlockTransactionsError::DuplicateInputInTransaction(
                        tx.get_id(),
                        block.get_id(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn check_duplicate_txs(&self, block: &Block) -> Result<(), CheckBlockTransactionsError> {
        // check duplicate transactions
        let mut txs_ids = BTreeSet::new();
        for tx in block.transactions() {
            let tx_id = tx.get_id();
            let already_in_tx_id = txs_ids.get(&tx_id);
            match already_in_tx_id {
                Some(_) => {
                    return Err(CheckBlockTransactionsError::DuplicatedTransactionInBlock(
                        tx_id,
                        block.get_id(),
                    ))
                }
                None => txs_ids.insert(tx_id),
            };
        }
        Ok(())
    }

    fn check_issue_data(
        &self,
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
        if metadata_uri.len() > TOKEN_MAX_URI_LEN
            || !String::from_utf8_lossy(metadata_uri).is_ascii()
        {
            return Err(TokensError::IssueErrorIncorrectMetadataURI(tx_id, block_id));
        }
        Ok(())
    }

    fn fetch_tx_by_output(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Transaction, CheckBlockTransactionsError> {
        let tx_index = self
            .db_tx
            .get_mainchain_tx_index(&outpoint.tx_id())
            .map_err(CheckBlockTransactionsError::StorageError)?
            .ok_or(CheckBlockTransactionsError::CheckTokensError(
                TokensError::NoTxInMainChainByOutpoint,
            ))?;
        match tx_index.position() {
            common::chain::SpendablePosition::Transaction(tx_pos) => {
                let tx = self
                    .db_tx
                    .get_mainchain_tx_by_position(tx_pos)
                    .map_err(CheckBlockTransactionsError::StorageError)?
                    .ok_or(CheckBlockTransactionsError::CheckTokensError(
                        TokensError::NoTxInMainChainByOutpoint,
                    ))?;

                Ok(tx)
            }
            common::chain::SpendablePosition::BlockReward(_) => {
                // Block reward in tokens is not allowed
                Err(CheckBlockTransactionsError::CheckTokensError(
                    TokensError::BlockRewardOutputCantBeUsedInTokenTx,
                ))
            }
        }
    }

    // Get TokenId and Amount in input
    fn map_tokens(&self, input: &common::chain::TxInput) -> Option<(TokenId, Amount)> {
        let output_index = input.outpoint().output_index() as usize;
        let prev_tx = self.fetch_tx_by_output(input.outpoint()).ok()?;
        match prev_tx.outputs().get(output_index)?.value() {
            OutputValue::Coin(_) => None,
            OutputValue::Asset(asset) => Some(match asset {
                AssetData::TokenTransferV1 { token_id, amount } => (*token_id, *amount),
                AssetData::TokenIssuanceV1 {
                    token_ticker: _,
                    amount_to_issue,
                    number_of_decimals: _,
                    metadata_uri: _,
                } => {
                    let token_id = token_id(&prev_tx)?;
                    (token_id, *amount_to_issue)
                }
                AssetData::TokenBurnV1 {
                    token_id: _,
                    amount_to_burn: _,
                } => {
                    /* Token have burned and can't be transfered */
                    return None;
                }
            }),
        }
    }

    fn check_transfer_data(
        &self,
        block_id: Id<Block>,
        tx: &Transaction,
        token_id: &TokenId,
        amount: &Amount,
    ) -> Result<(), TokensError> {
        // Collect token inputs
        let total_value_tokens = self.get_total_value_tokens(tx, &block_id)?;

        // Is token exist in inputs?
        let (_, origin_amount) = total_value_tokens
            .iter()
            .find(|&(origin_token_id, _)| origin_token_id == token_id)
            .ok_or_else(|| TokensError::NoTokenInInputs(tx.get_id(), block_id.clone()))?;

        // Check amount
        if origin_amount < amount || amount <= &Amount::from_atoms(0) {
            return Err(TokensError::InsuffienceTokenValueInInputs(
                tx.get_id(),
                block_id,
            ));
        }

        Ok(())
    }

    fn get_total_value_tokens(
        &self,
        tx: &Transaction,
        block_id: &Id<Block>,
    ) -> Result<BTreeMap<H256, Amount>, TokensError> {
        let mut total_value_of_input_tokens: BTreeMap<TokenId, Amount> = BTreeMap::new();
        tx.inputs().iter().filter_map(|input| self.map_tokens(input)).try_for_each(
            |(token_id, amount)| {
                total_value_of_input_tokens.insert(
                    token_id,
                    (total_value_of_input_tokens
                        .get(&token_id)
                        .cloned()
                        .unwrap_or(Amount::from_atoms(0))
                        + amount)
                        .ok_or_else(|| {
                            TokensError::CoinOrAssetOverflow(tx.get_id(), block_id.clone())
                        })?,
                );
                Ok(())
            },
        )?;
        Ok(total_value_of_input_tokens)
    }

    fn get_issuance_count(tx: &Transaction) -> usize {
        tx.outputs()
            .iter()
            .filter_map(|output| {
                match matches!(
                    output.value(),
                    OutputValue::Asset(AssetData::TokenIssuanceV1 {
                        token_ticker: _,
                        amount_to_issue: _,
                        number_of_decimals: _,
                        metadata_uri: _,
                    })
                ) {
                    true => Some(()),
                    false => None,
                }
            })
            .count()
    }

    fn check_tokens(&self, block: &Block) -> Result<(), CheckBlockTransactionsError> {
        const MAX_ISSUANCE_ALLOWED: usize = 1;

        for tx in block.transactions() {
            // We can't issue any count of token types in one tx
            let issuance_count = Self::get_issuance_count(tx);
            if issuance_count > MAX_ISSUANCE_ALLOWED {
                return Err(CheckBlockTransactionsError::CheckTokensError(
                    TokensError::MultipleTokenIssuanceInTransaction(tx.get_id(), block.get_id()),
                ));
            }

            // Check assets
            tx.outputs()
                .iter()
                .filter_map(|output| match output.value() {
                    OutputValue::Coin(_) => None,
                    OutputValue::Asset(asset) => Some(asset),
                })
                .try_for_each(|asset| self.check_asset(asset, tx, block))
                .map_err(CheckBlockTransactionsError::CheckTokensError)?;

            // If it is not a genesis and in tx issuance
            if self
                .db_tx
                .get_best_block_id()
                .map_err(CheckBlockTransactionsError::StorageError)?
                .is_some()
                && issuance_count == MAX_ISSUANCE_ALLOWED
            {
                // check is fee enough for issuance
                if !Self::is_issuance_fee_enough(
                    self.get_total_coins_in_inputs(tx, block.get_id())
                        .map_err(CheckBlockTransactionsError::CheckTokensError)?,
                    self.get_total_coins_in_outputs(tx, block.get_id())
                        .map_err(CheckBlockTransactionsError::CheckTokensError)?,
                ) {
                    return Err(CheckBlockTransactionsError::CheckTokensError(
                        TokensError::InsuffienceTokenFees(tx.get_id(), block.get_id()),
                    ));
                }
            }
        }
        Ok(())
    }

    fn get_total_coins_in_outputs(
        &self,
        tx: &Transaction,
        block_id: Id<Block>,
    ) -> Result<Amount, TokensError> {
        let res: Amount = tx
            .outputs()
            .iter()
            .filter_map(|output| match output.value() {
                OutputValue::Coin(coin) => Some(coin),
                OutputValue::Asset(_) => None,
            })
            .try_fold(Amount::from_atoms(0), |acc, coin| acc + *coin)
            .ok_or_else(|| TokensError::CoinOrAssetOverflow(tx.get_id(), block_id))?;
        Ok(res)
    }

    fn get_total_coins_in_inputs(
        &self,
        tx: &Transaction,
        block_id: Id<Block>,
    ) -> Result<Amount, TokensError> {
        tx.inputs()
            .iter()
            .filter_map(|input| {
                let prev_tx = self.fetch_tx_by_output(input.outpoint()).ok()?;
                let output = prev_tx.outputs().get(input.outpoint().output_index() as usize)?;
                Some(output.value().clone())
            })
            .filter_map(|output_value| match output_value {
                OutputValue::Coin(coin) => Some(coin),
                OutputValue::Asset(_) => None,
            })
            .try_fold(Amount::from_atoms(0), |acc, coin| {
                (acc + coin)
                    .ok_or_else(|| TokensError::CoinOrAssetOverflow(tx.get_id(), block_id.clone()))
            })
    }

    fn is_issuance_fee_enough(coins_in_inputs: Amount, coins_in_outputs: Amount) -> bool {
        (coins_in_inputs - coins_in_outputs).unwrap_or(Amount::from_atoms(0))
            > TOKEN_MIN_ISSUANCE_FEE
    }

    fn check_burn_data(
        &self,
        tx: &Transaction,
        block_id: &Id<Block>,
        burn_token_id: &TokenId,
        amount_to_burn: &Amount,
    ) -> Result<(), TokensError> {
        // Collect token inputs
        let total_value_tokens = self.get_total_value_tokens(tx, block_id)?;

        // Is token exist in inputs?
        let (_, origin_amount) = total_value_tokens
            .iter()
            .find(|&(origin_token_id, _)| origin_token_id == burn_token_id)
            .ok_or_else(|| TokensError::NoTokenInInputs(tx.get_id(), block_id.clone()))?;

        // Check amount
        if origin_amount < amount_to_burn {
            return Err(TokensError::InsuffienceTokenValueInInputs(
                tx.get_id(),
                block_id.clone(),
            ));
        }
        if amount_to_burn == &Amount::from_atoms(0) {
            return Err(TokensError::BurnZeroTokens(tx.get_id(), block_id.clone()));
        }

        // If we burn a piece of the token, we have to check output with the rest tokens
        if origin_amount > amount_to_burn {
            // Check whether all tokens burn and transfer
            if (*amount_to_burn + get_change_amount(tx, burn_token_id, block_id)?)
                != Some(*origin_amount)
            {
                return Err(TokensError::SomeTokensLost(tx.get_id(), block_id.clone()));
            }
        }
        Ok(())
    }

    fn check_asset(
        &self,
        asset: &AssetData,
        tx: &Transaction,
        block: &Block,
    ) -> Result<(), TokensError> {
        match asset {
            AssetData::TokenTransferV1 { token_id, amount } => {
                self.check_transfer_data(block.get_id(), tx, token_id, amount)?;
            }
            AssetData::TokenIssuanceV1 {
                token_ticker,
                amount_to_issue,
                number_of_decimals,
                metadata_uri,
            } => {
                self.check_issue_data(
                    token_ticker,
                    amount_to_issue,
                    number_of_decimals,
                    metadata_uri,
                    tx.get_id(),
                    block.get_id(),
                )?;
            }
            AssetData::TokenBurnV1 {
                token_id,
                amount_to_burn,
            } => {
                self.check_burn_data(tx, &block.get_id(), token_id, amount_to_burn)?;
            }
        }
        Ok(())
    }

    fn check_transactions(&self, block: &Block) -> Result<(), CheckBlockTransactionsError> {
        self.check_duplicate_inputs(block)?;
        self.check_duplicate_txs(block)?;
        self.check_tokens(block)?;
        Ok(())
    }

    fn get_block_from_index(&self, block_index: &BlockIndex) -> Result<Option<Block>, BlockError> {
        Ok(self.db_tx.get_block(block_index.block_id().clone())?)
    }

    pub fn check_block(&self, block: &Block) -> Result<(), CheckBlockError> {
        consensus_validator::validate_consensus(self.chain_config, block.header(), self)
            .map_err(CheckBlockError::ConsensusVerificationFailed)?;
        self.check_block_detail(block)?;
        Ok(())
    }

    fn get_block_proof(&self, block: &Block) -> Result<Uint256, BlockError> {
        block
            .header()
            .consensus_data()
            .get_block_proof()
            .ok_or_else(|| BlockError::BlockProofCalculationError(block.get_id()))
    }

    fn make_cache_with_connected_transactions(
        &self,
        block: &Block,
        spend_height: &BlockHeight,
        blockreward_maturity: &BlockDistance,
    ) -> Result<CachedInputs<S>, BlockError> {
        let mut cached_inputs = CachedInputs::new(&self.db_tx);

        cached_inputs.spend(
            BlockTransactableRef::BlockReward(block),
            spend_height,
            blockreward_maturity,
        )?;

        for (tx_num, _tx) in block.transactions().iter().enumerate() {
            cached_inputs.spend(
                BlockTransactableRef::Transaction(block, tx_num),
                spend_height,
                blockreward_maturity,
            )?;
        }

        let block_subsidy = self.chain_config.block_subsidy_at_height(spend_height);
        cached_inputs.check_block_reward(block, block_subsidy)?;

        Ok(cached_inputs)
    }

    fn make_cache_with_disconnected_transactions(
        &self,
        block: &Block,
    ) -> Result<CachedInputs<S>, BlockError> {
        let mut cached_inputs = CachedInputs::new(&self.db_tx);
        block.transactions().iter().enumerate().try_for_each(|(tx_num, _tx)| {
            cached_inputs.unspend(BlockTransactableRef::Transaction(block, tx_num))
        })?;
        cached_inputs.unspend(BlockTransactableRef::BlockReward(block))?;
        Ok(cached_inputs)
    }
}

// Calc not burned tokens that were placed in OutputValue::TokenTransfer after partial burn
fn get_change_amount(
    tx: &Transaction,
    burn_token_id: &H256,
    block_id: &Id<Block>,
) -> Result<Amount, TokensError> {
    let change_amount = tx
        .outputs()
        .iter()
        .filter_map(|x| match x.value() {
            OutputValue::Coin(_) => None,
            OutputValue::Asset(asset) => match asset {
                AssetData::TokenTransferV1 { token_id, amount } => {
                    if token_id == burn_token_id {
                        Some(amount)
                    } else {
                        None
                    }
                }
                AssetData::TokenIssuanceV1 {
                    token_ticker: _,
                    amount_to_issue: _,
                    number_of_decimals: _,
                    metadata_uri: _,
                }
                | AssetData::TokenBurnV1 {
                    token_id: _,
                    amount_to_burn: _,
                } => None,
            },
        })
        .try_fold(Amount::from_atoms(0), |accum, output| accum + *output)
        .ok_or_else(|| TokensError::CoinOrAssetOverflow(tx.get_id(), block_id.clone()))?;
    Ok(change_amount)
}

impl<'a, S: BlockchainStorageWrite, O: OrphanBlocksMut> ChainstateRef<'a, S, O> {
    pub fn check_legitimate_orphan(
        &mut self,
        block_source: BlockSource,
        block: Block,
    ) -> Result<Block, OrphanCheckError> {
        let prev_block_id = &match block.prev_block_id() {
            Some(id) => id,
            None => {
                if block.is_genesis(self.chain_config) {
                    return Ok(block);
                } else {
                    return Err(OrphanCheckError::PrevBlockIdNotFound);
                }
            }
        };

        let block_index_found = self
            .get_block_index(prev_block_id)
            .map_err(OrphanCheckError::PrevBlockIndexNotFound)?
            .is_some();

        if block_source == BlockSource::Local
            && !block.is_genesis(self.chain_config)
            && !block_index_found
        {
            self.new_orphan_block(block)?;
            return Err(OrphanCheckError::LocalOrphan);
        }
        Ok(block)
    }

    fn disconnect_until(
        &mut self,
        to_disconnect: &BlockIndex,
        last_to_remain_connected: &Id<Block>,
    ) -> Result<(), BlockError> {
        let mut to_disconnect_next = to_disconnect.clone();
        while to_disconnect_next.block_id() != last_to_remain_connected {
            to_disconnect_next = self.disconnect_tip(Some(to_disconnect_next.block_id()))?;
        }
        Ok(())
    }

    fn reorganize(
        &mut self,
        best_block_id: &Id<Block>,
        new_block_index: &BlockIndex,
    ) -> Result<(), BlockError> {
        let new_chain = self.get_new_chain(new_block_index).map_err(|e| {
            BlockError::InvariantErrorFailedToFindNewChainPath(
                new_block_index.block_id().clone(),
                best_block_id.clone(),
                e,
            )
        })?;

        let common_ancestor_id = {
            let err = "This vector cannot be empty since there is at least one block to connect";
            let first_block = &new_chain.first().expect(err);
            &first_block.prev_block_id().as_ref().expect("This can never be genesis")
        };

        // Disconnect the current chain if it is not a genesis
        {
            let mainchain_tip = self
                .db_tx
                .get_block_index(best_block_id)?
                .expect("Can't get block index. Inconsistent DB");

            // Disconnect blocks
            self.disconnect_until(&mainchain_tip, common_ancestor_id)?;
        }

        // Connect the new chain
        for block_index in new_chain {
            self.connect_tip(&block_index)?;
        }

        Ok(())
    }

    fn connect_transactions(
        &mut self,
        block: &Block,
        spend_height: &BlockHeight,
        blockreward_maturity: &BlockDistance,
    ) -> Result<(), BlockError> {
        let cached_inputs =
            self.make_cache_with_connected_transactions(block, spend_height, blockreward_maturity)?;
        let cached_inputs = cached_inputs.consume()?;

        CachedInputs::flush_to_storage(&mut self.db_tx, cached_inputs)?;
        Ok(())
    }

    fn disconnect_transactions(&mut self, block: &Block) -> Result<(), BlockError> {
        let cached_inputs = self.make_cache_with_disconnected_transactions(block)?;
        let cached_inputs = cached_inputs.consume()?;

        CachedInputs::flush_to_storage(&mut self.db_tx, cached_inputs)?;
        Ok(())
    }

    fn connect_genesis_transactions(&mut self, block: &Block) -> Result<(), BlockError> {
        for (num, tx) in block.transactions().iter().enumerate() {
            self.db_tx.set_mainchain_tx_index(
                &OutPointSourceId::from(tx.get_id()),
                &calculate_tx_index_from_block(block, num)
                    .expect("Index calculation for genesis failed"),
            )?;
        }
        Ok(())
    }

    // Connect new block
    fn connect_tip(&mut self, new_tip_block_index: &BlockIndex) -> Result<(), BlockError> {
        if &self.db_tx.get_best_block_id()? != new_tip_block_index.prev_block_id() {
            return Err(BlockError::InvariantErrorInvalidTip);
        }
        let block = self.get_block_from_index(new_tip_block_index)?.expect("Inconsistent DB");

        if block.is_genesis(self.chain_config) {
            self.connect_genesis_transactions(&block)?
        } else {
            self.connect_transactions(
                &block,
                &new_tip_block_index.block_height(),
                self.chain_config.blockreward_maturity(),
            )?;
        }

        self.db_tx.set_block_id_at_height(
            &new_tip_block_index.block_height(),
            new_tip_block_index.block_id(),
        )?;
        self.db_tx.set_block_index(new_tip_block_index)?;
        self.db_tx.set_best_block_id(new_tip_block_index.block_id())?;
        Ok(())
    }

    /// Does a read-modify-write operation on the database and disconnects a block
    /// by unsetting the `next` pointer.
    /// Returns the previous block (the last block in the main-chain)
    fn disconnect_tip(
        &mut self,
        expected_tip_block_id: Option<&Id<Block>>,
    ) -> Result<BlockIndex, BlockError> {
        let best_block_id =
            self.db_tx.get_best_block_id().ok().flatten().expect("Only fails at genesis");

        // Optionally, we can double-check that the tip is what we're discconnecting
        match expected_tip_block_id {
            None => {}
            Some(expected_tip_block_id) => debug_assert!(expected_tip_block_id == &best_block_id),
        }

        let block_index = self
            .db_tx
            .get_block_index(&best_block_id)
            .expect("Database error on retrieving current best block index")
            .expect("Also only genesis fails at this");
        let block = self.get_block_from_index(&block_index)?.expect("Inconsistent DB");

        // Disconnect transactions
        self.disconnect_transactions(&block)?;
        self.db_tx.set_best_block_id(
            block_index
                .prev_block_id()
                .as_ref()
                .ok_or(BlockError::InvariantErrorPrevBlockNotFound)?,
        )?;
        // Disconnect block
        self.db_tx.del_block_id_at_height(&block_index.block_height())?;

        let prev_block_index = self
            .get_previous_block_index(&block_index)
            .expect("Failed to continue disconnection of blocks and reached genesis");
        Ok(prev_block_index)
    }

    fn try_connect_genesis_block(
        &mut self,
        genesis_block_index: &BlockIndex,
        best_block_id: &Option<Id<Block>>,
    ) -> Result<Option<BlockIndex>, BlockError> {
        if best_block_id.is_none() && genesis_block_index.is_genesis(self.chain_config) {
            self.connect_tip(genesis_block_index)?;
            return Ok(Some(genesis_block_index.clone()));
        }
        Ok(None)
    }

    pub fn activate_best_chain(
        &mut self,
        new_block_index: BlockIndex,
        best_block_id: Option<Id<Block>>,
    ) -> Result<Option<BlockIndex>, BlockError> {
        let connected_genesis = self.try_connect_genesis_block(&new_block_index, &best_block_id)?;
        if connected_genesis.is_some() {
            return Ok(connected_genesis);
        }

        let best_block_id = best_block_id.expect("Best block must be set at this point");
        // Chain trust is higher than the best block
        let current_best_block_index = self
            .db_tx
            .get_block_index(&best_block_id)
            .map_err(BlockError::from)?
            .expect("Inconsistent DB");

        if new_block_index.chain_trust() > current_best_block_index.chain_trust() {
            self.reorganize(&best_block_id, &new_block_index)?;
            return Ok(Some(new_block_index));
        }

        Ok(None)
    }

    fn add_to_block_index(&mut self, block: &Block) -> Result<BlockIndex, BlockError> {
        match self.db_tx.get_block_index(&block.get_id()).map_err(BlockError::from)? {
            // this is not an error, because it's valid to have the header but not the whole block
            Some(bi) => return Ok(bi),
            None => (),
        }

        let prev_block_index = if block.is_genesis(self.chain_config) {
            // Genesis case. We should use then_some when stabilized feature(bool_to_option)
            None
        } else {
            block.prev_block_id().map_or(Err(BlockError::PrevBlockNotFound), |prev_block| {
                self.db_tx.get_block_index(&prev_block).map_err(BlockError::from)
            })?
        };
        // Set the block height
        let height = prev_block_index.as_ref().map_or(BlockHeight::zero(), |prev_block_index| {
            prev_block_index.block_height().next_height()
        });

        let some_ancestor = prev_block_index.as_ref().map(|prev_bi| {
            self.get_ancestor(prev_bi, get_skip_height(height))
                .unwrap_or_else(|_| {
                    panic!("Ancestor retrieval failed for block: {}", block.get_id())
                })
                .block_id()
                .clone()
        });

        // Set Time Max
        let time_max = prev_block_index.as_ref().map_or(block.timestamp(), |prev_block_index| {
            std::cmp::max(prev_block_index.chain_timestamps_max(), block.timestamp())
        });

        // Set Chain Trust
        let prev_chain_trust = prev_block_index.map_or(Uint256::from_u64(0), |prev_block_index| {
            *prev_block_index.chain_trust()
        });
        let chain_trust = prev_chain_trust + self.get_block_proof(block)?;
        let block_index = BlockIndex::new(block, chain_trust, some_ancestor, height, time_max);
        Ok(block_index)
    }

    pub fn accept_block(&mut self, block: &Block) -> Result<BlockIndex, BlockError> {
        let block_index = self.add_to_block_index(block)?;
        match self.db_tx.get_block(block.get_id()).map_err(BlockError::from)? {
            Some(_) => return Err(BlockError::BlockAlreadyExists(block.get_id())),
            None => (),
        }
        self.check_block_index(&block_index)?;
        self.db_tx.set_block_index(&block_index).map_err(BlockError::from)?;
        self.db_tx.add_block(block).map_err(BlockError::from)?;
        Ok(block_index)
    }

    /// Mark new block as an orphan
    fn new_orphan_block(&mut self, block: Block) -> Result<(), OrphanCheckError> {
        // It can't be a genesis block
        assert!(!block.is_genesis(self.chain_config));
        match self.orphan_blocks.add_block(block) {
            Ok(_) => Ok(()),
            Err(err) => err.into(),
        }
    }
}
