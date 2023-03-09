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

use std::{collections::BTreeSet, convert::TryInto};

use chainstate_storage::{
    BlockchainStorageRead, BlockchainStorageWrite, SealedStorageTag, TransactionRw,
};
use chainstate_types::{
    block_index_ancestor_getter, get_skip_height, BlockIndex, BlockIndexHandle,
    BlockPreconnectData, ConsensusExtraData, EpochData, GenBlockIndex, GetAncestorError,
    PropertyQueryError,
};
use common::{
    chain::{
        block::{
            calculate_tx_merkle_root, calculate_witness_merkle_root, BlockHeader, BlockReward,
        },
        tokens::TokenAuxiliaryData,
        tokens::{get_tokens_issuance_count, OutputValue, TokenId},
        Block, ChainConfig, GenBlock, GenBlockId, OutPointSourceId, Transaction,
    },
    primitives::{id::WithId, BlockDistance, BlockHeight, Id, Idable},
    time_getter::TimeGetter,
    Uint256,
};
use consensus::compute_extra_consensus_data;
use logging::log;
use pos_accounting::PoSAccountingDB;
use tx_verifier::transaction_verifier::{config::TransactionVerifierConfig, TransactionVerifier};
use utils::{ensure, tap_error_log::LogError};
use utxo::{UtxosDB, UtxosView};

use crate::{BlockError, ChainstateConfig};

use self::tx_verifier_storage::gen_block_index_getter;

use super::{
    median_time::calculate_median_time_past,
    tokens::check_tokens_data,
    transaction_verifier::{error::TokensError, flush::flush_to_storage},
    tx_verification_strategy::TransactionVerificationStrategy,
    BlockSizeError, CheckBlockError, CheckBlockTransactionsError,
};

mod epoch_seal;
mod tx_verifier_storage;

pub struct ChainstateRef<'a, S, V> {
    chain_config: &'a ChainConfig,
    chainstate_config: &'a ChainstateConfig,
    tx_verification_strategy: &'a V,
    db_tx: S,
    time_getter: &'a TimeGetter,
}

impl<'a, S: BlockchainStorageRead, V: TransactionVerificationStrategy> BlockIndexHandle
    for ChainstateRef<'a, S, V>
{
    fn get_block_index(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError> {
        self.get_block_index(block_id)
    }

    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
        self.get_gen_block_index(block_id)
    }

    fn get_ancestor(
        &self,
        block_index: &BlockIndex,
        ancestor_height: BlockHeight,
    ) -> Result<GenBlockIndex, PropertyQueryError> {
        self.get_ancestor(&GenBlockIndex::Block(block_index.clone()), ancestor_height)
            .map_err(PropertyQueryError::from)
    }

    fn get_block_reward(
        &self,
        block_index: &BlockIndex,
    ) -> Result<Option<BlockReward>, PropertyQueryError> {
        self.get_block_reward(block_index)
    }

    fn get_epoch_data(&self, epoch_index: u64) -> Result<Option<EpochData>, PropertyQueryError> {
        self.db_tx.get_epoch_data(epoch_index).map_err(PropertyQueryError::from)
    }
}

impl<'a, S: TransactionRw, V> ChainstateRef<'a, S, V> {
    pub fn commit_db_tx(self) -> chainstate_storage::Result<()> {
        self.db_tx.commit()
    }
}

impl<'a, S: BlockchainStorageRead, V: TransactionVerificationStrategy> ChainstateRef<'a, S, V> {
    pub fn new_rw(
        chain_config: &'a ChainConfig,
        chainstate_config: &'a ChainstateConfig,
        tx_verification_strategy: &'a V,
        db_tx: S,
        time_getter: &'a TimeGetter,
    ) -> ChainstateRef<'a, S, V> {
        ChainstateRef {
            chain_config,
            chainstate_config,
            db_tx,
            tx_verification_strategy,
            time_getter,
        }
    }

    pub fn new_ro(
        chain_config: &'a ChainConfig,
        chainstate_config: &'a ChainstateConfig,
        tx_verification_strategy: &'a V,
        db_tx: S,
        time_getter: &'a TimeGetter,
    ) -> ChainstateRef<'a, S, V> {
        ChainstateRef {
            chain_config,
            chainstate_config,
            db_tx,
            tx_verification_strategy,
            time_getter,
        }
    }

    // TODO: When the mempool incorporates the transaction-verifier, this won't be needed anymore
    pub fn make_utxo_view(&self) -> impl UtxosView + '_ {
        UtxosDB::new(&self.db_tx)
    }

    pub fn chain_config(&self) -> &ChainConfig {
        self.chain_config
    }

    pub fn current_time(&self) -> std::time::Duration {
        self.time_getter.get_time()
    }

    pub fn get_best_block_id(&self) -> Result<Id<GenBlock>, PropertyQueryError> {
        self.db_tx
            .get_best_block_id()
            .map_err(PropertyQueryError::from)
            .map(|bid| bid.expect("Best block ID not initialized"))
    }

    pub fn get_block_index(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError> {
        log::trace!("Loading block index of id: {}", block_id);
        self.db_tx.get_block_index(block_id).map_err(PropertyQueryError::from)
    }

    pub fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
        gen_block_index_getter(&self.db_tx, self.chain_config, block_id)
            .map_err(PropertyQueryError::from)
    }

    pub fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<common::chain::TxMainChainIndex>, PropertyQueryError> {
        log::trace!("Loading transaction index of id: {:?}", tx_id);
        self.db_tx.get_mainchain_tx_index(tx_id).map_err(PropertyQueryError::from)
    }

    pub fn get_block_id_by_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, PropertyQueryError> {
        self.db_tx.get_block_id_by_height(height).map_err(PropertyQueryError::from)
    }

    pub fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, PropertyQueryError> {
        self.db_tx.get_block(block_id).map_err(PropertyQueryError::from)
    }

    pub fn is_block_in_main_chain(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<bool, PropertyQueryError> {
        let ht = match self.get_block_height_in_main_chain(block_id).log_err()? {
            None => return Ok(false),
            Some(ht) => ht,
        };
        let bid = self.get_block_id_by_height(&ht).log_err()?;
        Ok(bid == Some(*block_id))
    }

    /// Read previous block from storage and return its BlockIndex
    fn get_previous_block_index(
        &self,
        block_index: &BlockIndex,
    ) -> Result<GenBlockIndex, PropertyQueryError> {
        let prev_block_id = block_index.prev_block_id();
        self.get_gen_block_index(prev_block_id)
            .log_err()?
            .ok_or(PropertyQueryError::PrevBlockIndexNotFound(*prev_block_id))
    }

    pub fn get_ancestor(
        &self,
        block_index: &GenBlockIndex,
        target_height: BlockHeight,
    ) -> Result<GenBlockIndex, GetAncestorError> {
        block_index_ancestor_getter(
            gen_block_index_getter,
            &self.db_tx,
            self.chain_config,
            block_index.into(),
            target_height,
        )
    }

    pub fn last_common_ancestor(
        &self,
        first_block_index: &GenBlockIndex,
        second_block_index: &GenBlockIndex,
    ) -> Result<GenBlockIndex, PropertyQueryError> {
        let mut first_block_index = first_block_index.clone();
        let mut second_block_index = second_block_index.clone();
        match first_block_index.block_height().cmp(&second_block_index.block_height()) {
            std::cmp::Ordering::Greater => {
                first_block_index = self
                    .get_ancestor(&first_block_index, second_block_index.block_height())
                    .log_err()?;
            }
            std::cmp::Ordering::Less => {
                second_block_index = self
                    .get_ancestor(&second_block_index, first_block_index.block_height())
                    .log_err()?;
            }
            std::cmp::Ordering::Equal => {}
        }

        loop {
            match (&first_block_index, &second_block_index) {
                _ if first_block_index.block_id() == second_block_index.block_id() => {
                    break Ok(first_block_index)
                }
                (GenBlockIndex::Block(first_blkidx), GenBlockIndex::Block(second_blkidx)) => {
                    first_block_index = self.get_previous_block_index(first_blkidx).log_err()?;
                    second_block_index = self.get_previous_block_index(second_blkidx).log_err()?;
                }
                _ => panic!("Chain iteration not in lockstep"),
            }
        }
    }

    pub fn get_best_block_index(&self) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
        self.get_gen_block_index(&self.get_best_block_id().log_err()?)
    }

    pub fn get_token_aux_data(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<TokenAuxiliaryData>, PropertyQueryError> {
        self.db_tx.get_token_aux_data(token_id).map_err(PropertyQueryError::from)
    }

    pub fn get_token_id(
        &self,
        tx_id: &Id<Transaction>,
    ) -> Result<Option<TokenId>, PropertyQueryError> {
        self.db_tx.get_token_id(tx_id).map_err(PropertyQueryError::from)
    }

    pub fn get_header_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<BlockHeader>, PropertyQueryError> {
        let id = self
            .get_block_id_by_height(height)
            .log_err()?
            .ok_or(PropertyQueryError::BlockForHeightNotFound(*height))
            .log_err()?;
        let id = id
            .classify(self.chain_config)
            .chain_block_id()
            .ok_or(PropertyQueryError::GenesisHeaderRequested)
            .log_err()?;
        Ok(self
            .get_block_index(&id)
            .log_err()?
            .map(|block_index| block_index.into_block_header()))
    }

    pub fn get_block_reward(
        &self,
        block_index: &BlockIndex,
    ) -> Result<Option<BlockReward>, PropertyQueryError> {
        Ok(self.db_tx.get_block_reward(block_index).log_err()?)
    }

    pub fn get_block_height_in_main_chain(
        &self,
        id: &Id<GenBlock>,
    ) -> Result<Option<BlockHeight>, PropertyQueryError> {
        let id = match id.classify(self.chain_config) {
            GenBlockId::Block(id) => id,
            GenBlockId::Genesis(_) => return Ok(Some(BlockHeight::zero())),
        };
        let block_index = self.get_block_index(&id).log_err()?;
        let block_index = block_index.ok_or(PropertyQueryError::BlockNotFound(id)).log_err()?;
        if block_index.block_id() == &id {
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
        while !self.is_block_in_main_chain(&(*block_index.block_id()).into()).log_err()? {
            result.push(block_index.clone());
            block_index = match self.get_previous_block_index(&block_index).log_err()? {
                GenBlockIndex::Genesis(_) => break,
                GenBlockIndex::Block(blkidx) => blkidx,
            }
        }
        result.reverse();
        debug_assert!(!result.is_empty()); // there has to always be at least one new block
        Ok(result)
    }

    fn check_block_index(&self, block_index: &BlockIndex) -> Result<(), BlockError> {
        // BlockIndex is already known or block exists
        if self.db_tx.get_block_index(block_index.block_id()).log_err()?.is_some() {
            return Err(BlockError::BlockAlreadyExists(*block_index.block_id()));
        }
        // TODO: Will be expanded
        Ok(())
    }

    pub fn check_block_header(&self, header: &BlockHeader) -> Result<(), CheckBlockError> {
        self.check_header_size(header).log_err()?;

        let utxos_db = UtxosDB::new(&self.db_tx);
        let pos_db = PoSAccountingDB::<_, SealedStorageTag>::new(&self.db_tx);
        consensus::validate_consensus(self.chain_config, header, self, &utxos_db, &pos_db)
            .map_err(CheckBlockError::ConsensusVerificationFailed)
            .log_err()?;

        let prev_block_id = header.prev_block_id();
        let median_time_past = calculate_median_time_past(self, prev_block_id);
        ensure!(
            header.timestamp() >= median_time_past,
            CheckBlockError::BlockTimeOrderInvalid,
        );

        let max_future_offset = self.chain_config.max_future_block_time_offset();
        let current_time = self.current_time();
        let block_timestamp = header.timestamp();
        ensure!(
            block_timestamp.as_duration_since_epoch() <= current_time + *max_future_offset,
            CheckBlockError::BlockFromTheFuture,
        );
        Ok(())
    }

    fn check_block_reward_maturity_settings(&self, block: &Block) -> Result<(), CheckBlockError> {
        let required = block.consensus_data().reward_maturity_distance(self.chain_config);
        for output in block.block_reward().outputs() {
            match output.purpose() {
                common::chain::OutputPurpose::Transfer(_) => {
                    return Err(CheckBlockError::InvalidBlockRewardOutputType(
                        block.get_id(),
                    ))
                }
                common::chain::OutputPurpose::LockThenTransfer(_, tl) => match tl {
                    common::chain::timelock::OutputTimeLock::UntilHeight(_) => {
                        return Err(CheckBlockError::InvalidBlockRewardMaturityTimelockType(
                            block.get_id(),
                        ))
                    }
                    common::chain::timelock::OutputTimeLock::UntilTime(_) => {
                        return Err(CheckBlockError::InvalidBlockRewardMaturityTimelockType(
                            block.get_id(),
                        ))
                    }
                    common::chain::timelock::OutputTimeLock::ForBlockCount(c) => {
                        let cs: i64 = (*c)
                            .try_into()
                            .map_err(|_| {
                                CheckBlockError::InvalidBlockRewardMaturityDistanceValue(
                                    block.get_id(),
                                    *c,
                                )
                            })
                            .log_err()?;
                        let given = BlockDistance::new(cs);
                        if given < required {
                            return Err(CheckBlockError::InvalidBlockRewardMaturityDistance(
                                block.get_id(),
                                given,
                                required,
                            ));
                        }
                    }
                    common::chain::timelock::OutputTimeLock::ForSeconds(_) => {
                        return Err(CheckBlockError::InvalidBlockRewardMaturityTimelockType(
                            block.get_id(),
                        ))
                    }
                },
                common::chain::OutputPurpose::StakePool(_) => {
                    return Err(CheckBlockError::InvalidBlockRewardOutputType(
                        block.get_id(),
                    ))
                }
                common::chain::OutputPurpose::Burn => {
                    return Err(CheckBlockError::InvalidBlockRewardOutputType(
                        block.get_id(),
                    ))
                }
            }
        }
        Ok(())
    }

    fn check_header_size(&self, header: &BlockHeader) -> Result<(), BlockSizeError> {
        let size = header.header_size();
        ensure!(
            size <= self.chain_config.max_block_header_size(),
            BlockSizeError::Header(size, self.chain_config.max_block_header_size())
        );

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

    fn check_witness_count(&self, block: &Block) -> Result<(), CheckBlockTransactionsError> {
        for tx in block.transactions() {
            ensure!(
                tx.inputs().len() == tx.signatures().len(),
                CheckBlockTransactionsError::InvalidWitnessCount
            )
        }
        Ok(())
    }

    fn check_duplicate_inputs(&self, block: &Block) -> Result<(), CheckBlockTransactionsError> {
        // check for duplicate inputs (see CVE-2018-17144)
        let mut block_inputs = BTreeSet::new();
        for tx in block.transactions() {
            if tx.inputs().is_empty() || tx.outputs().is_empty() {
                return Err(
                    CheckBlockTransactionsError::EmptyInputsOutputsInTransactionInBlock(
                        tx.transaction().get_id(),
                        block.get_id(),
                    ),
                );
            }
            let mut tx_inputs = BTreeSet::new();
            for input in tx.inputs() {
                ensure!(
                    tx_inputs.insert(input.outpoint()),
                    CheckBlockTransactionsError::DuplicateInputInTransaction(
                        tx.transaction().get_id(),
                        block.get_id()
                    )
                );
                ensure!(
                    block_inputs.insert(input.outpoint()),
                    CheckBlockTransactionsError::DuplicateInputInBlock(block.get_id())
                );
            }
        }
        Ok(())
    }

    fn check_tokens_txs(&self, block: &Block) -> Result<(), CheckBlockTransactionsError> {
        for tx in block.transactions() {
            // We can't issue multiple tokens in a single tx
            let issuance_count = get_tokens_issuance_count(tx.outputs());
            ensure!(
                issuance_count <= 1,
                CheckBlockTransactionsError::TokensError(
                    TokensError::MultipleTokenIssuanceInTransaction(
                        tx.transaction().get_id(),
                        block.get_id()
                    ),
                )
            );

            // Check tokens
            tx.outputs()
                .iter()
                .filter_map(|output| match output.value() {
                    OutputValue::Coin(_) => None,
                    OutputValue::Token(token_data) => Some(token_data),
                })
                .try_for_each(|token_data| {
                    check_tokens_data(
                        self.chain_config,
                        token_data,
                        tx.transaction(),
                        block.get_id(),
                    )
                })
                .map_err(CheckBlockTransactionsError::TokensError)
                .log_err()?;
        }
        Ok(())
    }

    fn check_transactions(&self, block: &Block) -> Result<(), CheckBlockTransactionsError> {
        // Note: duplicate txs are detected through duplicate inputs
        self.check_witness_count(block).log_err()?;
        self.check_duplicate_inputs(block).log_err()?;
        self.check_tokens_txs(block).log_err()?;
        Ok(())
    }

    fn get_block_from_index(&self, block_index: &BlockIndex) -> Result<Option<Block>, BlockError> {
        Ok(self.db_tx.get_block(*block_index.block_id()).log_err()?)
    }

    pub fn check_block(&self, block: &WithId<Block>) -> Result<(), CheckBlockError> {
        self.check_block_header(block.header()).log_err()?;

        self.check_block_size(block)
            .map_err(CheckBlockError::BlockSizeError)
            .log_err()?;

        self.check_block_reward_maturity_settings(block).log_err()?;

        // MerkleTree root
        let merkle_tree_root = block.merkle_root();
        calculate_tx_merkle_root(block.body())
            .map_or(Err(CheckBlockError::MerkleRootMismatch), |merkle_tree| {
                ensure!(
                    merkle_tree_root == merkle_tree,
                    CheckBlockError::MerkleRootMismatch
                );
                Ok(())
            })
            .log_err()?;

        // Witness merkle root
        let witness_merkle_root = block.witness_merkle_root();
        calculate_witness_merkle_root(block.body())
            .map_or(
                Err(CheckBlockError::WitnessMerkleRootMismatch),
                |witness_merkle| {
                    ensure!(
                        witness_merkle_root == witness_merkle,
                        CheckBlockError::WitnessMerkleRootMismatch,
                    );
                    Ok(())
                },
            )
            .log_err()?;

        self.check_transactions(block)
            .map_err(CheckBlockError::CheckTransactionFailed)
            .log_err()?;

        Ok(())
    }

    fn get_block_proof(&self, block: &Block) -> Result<Uint256, BlockError> {
        block
            .header()
            .consensus_data()
            .get_block_proof()
            .ok_or_else(|| BlockError::BlockProofCalculationError(block.get_id()))
    }

    pub fn get_mainchain_blocks_list(&self) -> Result<Vec<Id<Block>>, PropertyQueryError> {
        let id_from_height = |block_height: u64| -> Result<Id<Block>, PropertyQueryError> {
            let block_height: BlockHeight = block_height.into();
            let block_id = self
                .get_block_id_by_height(&block_height)
                .log_err()?
                .expect("Since block_height is >= best_height, this must exist");
            let block_id = block_id
                .classify(self.chain_config)
                .chain_block_id()
                .expect("Since the height is never zero, this cannot be genesis");
            Ok(block_id)
        };

        let best_block_index =
            self.get_best_block_index().log_err()?.expect("Failed to get best block index");
        let best_height = best_block_index.block_height();
        let best_height_int: u64 = best_height.into();
        let mut result = Vec::with_capacity(best_height_int as usize);
        for block_height in 1..=best_height_int {
            result.push(id_from_height(block_height).log_err()?);
        }
        Ok(result)
    }

    pub fn get_block_id_tree_as_list(&self) -> Result<Vec<Id<Block>>, PropertyQueryError> {
        let block_tree_map = self.db_tx.get_block_tree_by_height().log_err()?;
        let result = block_tree_map
            .into_iter()
            .flat_map(|(_height, ids_per_height)| ids_per_height)
            .collect();
        Ok(result)
    }
}

impl<'a, S: BlockchainStorageWrite, V: TransactionVerificationStrategy> ChainstateRef<'a, S, V> {
    fn disconnect_until(
        &mut self,
        to_disconnect: &BlockIndex,
        last_to_remain_connected: &Id<GenBlock>,
    ) -> Result<(), BlockError> {
        let mut to_disconnect = GenBlockIndex::Block(to_disconnect.clone());
        while to_disconnect.block_id() != *last_to_remain_connected {
            let to_disconnect_block = match to_disconnect {
                GenBlockIndex::Genesis(_) => panic!("Attempt to disconnect genesis"),
                GenBlockIndex::Block(block_index) => block_index,
            };
            to_disconnect = self.disconnect_tip(Some(to_disconnect_block.block_id())).log_err()?;
            self.post_disconnect_tip(to_disconnect.block_height()).log_err()?;
        }
        Ok(())
    }

    fn reorganize(
        &mut self,
        best_block_id: &Id<GenBlock>,
        new_block_index: &BlockIndex,
    ) -> Result<(), BlockError> {
        let new_chain = self
            .get_new_chain(new_block_index)
            .map_err(|e| {
                BlockError::InvariantErrorFailedToFindNewChainPath(
                    *new_block_index.block_id(),
                    *best_block_id,
                    e,
                )
            })
            .log_err()?;

        let common_ancestor_id = {
            let err = "This vector cannot be empty since there is at least one block to connect";
            let first_block = new_chain.first().expect(err);
            first_block.prev_block_id()
        };

        // Disconnect the current chain if it is not a genesis
        if let GenBlockId::Block(best_block_id) = best_block_id.classify(self.chain_config) {
            let mainchain_tip = self
                .get_block_index(&best_block_id)
                .map_err(BlockError::BestBlockLoadError)
                .log_err()?
                .expect("Can't get block index. Inconsistent DB");

            // Disconnect blocks
            self.disconnect_until(&mainchain_tip, common_ancestor_id).log_err()?;
        }

        // Connect the new chain
        for block_index in new_chain {
            self.connect_tip(&block_index).log_err()?;
            self.post_connect_tip(&block_index).log_err()?;
        }

        Ok(())
    }

    fn connect_transactions(
        &mut self,
        block_index: &BlockIndex,
        block: &WithId<Block>,
    ) -> Result<(), BlockError> {
        let verifier_config = TransactionVerifierConfig {
            tx_index_enabled: *self.chainstate_config.tx_index_enabled,
        };
        let connected_txs = self
            .tx_verification_strategy
            .connect_block(
                TransactionVerifier::new,
                self,
                &*self,
                self.chain_config,
                verifier_config,
                block_index,
                block,
            )
            .log_err()?;

        let consumed = connected_txs.consume()?;
        flush_to_storage(self, consumed)?;

        Ok(())
    }

    fn disconnect_transactions(&mut self, block: &WithId<Block>) -> Result<(), BlockError> {
        let verifier_config = TransactionVerifierConfig {
            tx_index_enabled: *self.chainstate_config.tx_index_enabled,
        };
        let cached_inputs = self.tx_verification_strategy.disconnect_block(
            TransactionVerifier::new,
            &*self,
            self.chain_config,
            verifier_config,
            block,
        )?;
        let cached_inputs = cached_inputs.consume()?;
        flush_to_storage(self, cached_inputs)?;

        Ok(())
    }

    // Connect new block
    fn connect_tip(&mut self, new_tip_block_index: &BlockIndex) -> Result<(), BlockError> {
        let best_block_id =
            self.get_best_block_id().map_err(BlockError::BestBlockLoadError).log_err()?;
        utils::ensure!(
            &best_block_id == new_tip_block_index.prev_block_id(),
            BlockError::InvariantErrorInvalidTip,
        );
        let block = self
            .get_block_from_index(new_tip_block_index)
            .log_err()?
            .expect("Inconsistent DB");

        self.connect_transactions(new_tip_block_index, &block.into()).log_err()?;

        self.db_tx
            .set_block_id_at_height(
                &new_tip_block_index.block_height(),
                &(*new_tip_block_index.block_id()).into(),
            )
            .log_err()?;
        self.db_tx
            .set_best_block_id(&(*new_tip_block_index.block_id()).into())
            .log_err()?;
        Ok(())
    }

    /// Does a read-modify-write operation on the database and disconnects a block
    /// by unsetting the `next` pointer.
    /// Returns the previous block (the last block in the main-chain)
    fn disconnect_tip(
        &mut self,
        expected_tip_block_id: Option<&Id<Block>>,
    ) -> Result<GenBlockIndex, BlockError> {
        let best_block_id = self
            .get_best_block_id()
            .expect("Best block not initialized")
            .classify(self.chain_config)
            .chain_block_id()
            .expect("Cannot disconnect genesis");

        // Optionally, we can double-check that the tip is what we're disconnecting
        if let Some(expected_tip_block_id) = expected_tip_block_id {
            debug_assert_eq!(expected_tip_block_id, &best_block_id);
        }

        let block_index = self
            .get_block_index(&best_block_id)
            .expect("Database error on retrieving current best block index")
            .expect("Best block index not present in the database");
        let block = self.get_block_from_index(&block_index).log_err()?.expect("Inconsistent DB");
        // Disconnect transactions
        self.disconnect_transactions(&block.into()).log_err()?;
        self.db_tx.set_best_block_id(block_index.prev_block_id()).log_err()?;
        // Disconnect block
        self.db_tx.del_block_id_at_height(&block_index.block_height()).log_err()?;

        let prev_block_index = self
            .get_previous_block_index(&block_index)
            .expect("Previous block index retrieval failed");
        Ok(prev_block_index)
    }

    pub fn activate_best_chain(
        &mut self,
        new_block_index: BlockIndex,
        best_block_id: Id<GenBlock>,
    ) -> Result<Option<BlockIndex>, BlockError> {
        // Chain trust is higher than the best block
        let current_best_block_index = self
            .get_gen_block_index(&best_block_id)
            .map_err(BlockError::BestBlockLoadError)
            .log_err()?
            .expect("Inconsistent DB");

        if new_block_index.chain_trust() > current_best_block_index.chain_trust() {
            self.reorganize(&best_block_id, &new_block_index).log_err()?;
            return Ok(Some(new_block_index));
        }

        Ok(None)
    }

    fn add_to_block_index(&mut self, block: &WithId<Block>) -> Result<BlockIndex, BlockError> {
        if let Some(bi) = self
            .db_tx
            .get_block_index(&block.get_id())
            .map_err(BlockError::from)
            .log_err()?
        {
            return Ok(bi);
        }

        let prev_block_index = self
            .get_gen_block_index(&block.prev_block_id())
            .map_err(BlockError::BestBlockLoadError)
            .log_err()?
            .ok_or(BlockError::PrevBlockNotFound)
            .log_err()?;

        // Set the block height
        let height = prev_block_index.block_height().next_height();

        let some_ancestor = {
            let skip_ht = get_skip_height(height);
            let err = |_| panic!("Ancestor retrieval failed for block: {}", block.get_id());
            self.get_ancestor(&prev_block_index, skip_ht).unwrap_or_else(err).block_id()
        };

        // Set Time Max
        let time_max = std::cmp::max(prev_block_index.chain_timestamps_max(), block.timestamp());

        // Set Chain Trust
        let utxos_db = UtxosDB::new(&self.db_tx);
        let consensus_extra = match &prev_block_index {
            GenBlockIndex::Block(prev_bi) => {
                compute_extra_consensus_data(self.chain_config, prev_bi, block.header(), &utxos_db)?
            }
            GenBlockIndex::Genesis(_) => ConsensusExtraData::None,
        };

        let chain_trust =
            *prev_block_index.chain_trust() + self.get_block_proof(block).log_err()?;
        let block_index = BlockIndex::new(
            block,
            chain_trust,
            some_ancestor,
            height,
            time_max,
            BlockPreconnectData::new(consensus_extra),
        );
        Ok(block_index)
    }

    pub fn accept_block(&mut self, block: &WithId<Block>) -> Result<BlockIndex, BlockError> {
        let block_index = self.add_to_block_index(block).log_err()?;
        if (self.db_tx.get_block(block.get_id()).map_err(BlockError::from).log_err()?).is_some() {
            return Err(BlockError::BlockAlreadyExists(block.get_id()));
        }

        self.check_block_index(&block_index).log_err()?;
        self.db_tx.set_block_index(&block_index).map_err(BlockError::from).log_err()?;
        self.db_tx.add_block(block).map_err(BlockError::from).log_err()?;
        Ok(block_index)
    }

    fn post_connect_tip(&mut self, tip_index: &BlockIndex) -> Result<(), BlockError> {
        epoch_seal::update_epoch_seal(
            &mut self.db_tx,
            self.chain_config,
            epoch_seal::BlockStateEvent::Connect(tip_index.block_height()),
        )?;
        epoch_seal::update_epoch_data(
            &mut self.db_tx,
            self.chain_config,
            epoch_seal::BlockStateEventWithIndex::Connect(tip_index.block_height(), tip_index),
        )
    }

    fn post_disconnect_tip(&mut self, tip_height: BlockHeight) -> Result<(), BlockError> {
        epoch_seal::update_epoch_seal(
            &mut self.db_tx,
            self.chain_config,
            epoch_seal::BlockStateEvent::Disconnect(tip_height),
        )?;
        epoch_seal::update_epoch_data(
            &mut self.db_tx,
            self.chain_config,
            epoch_seal::BlockStateEventWithIndex::Disconnect(tip_height),
        )
    }
}
