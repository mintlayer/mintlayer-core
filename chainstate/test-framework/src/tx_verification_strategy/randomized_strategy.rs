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

use std::{cell::RefCell, collections::VecDeque};

use chainstate::{
    calculate_median_time_past,
    tx_verification_strategy_utils::{
        construct_reward_tx_indices, construct_tx_indices, take_tx_index,
    },
    BlockError, TransactionVerificationStrategy,
};
use chainstate_types::{BlockIndex, BlockIndexHandle};
use common::{
    chain::{block::timestamp::BlockTimestamp, Block, ChainConfig, TxMainChainIndex},
    primitives::{id::WithId, Amount, Idable},
};
use crypto::random::{Rng, RngCore};
use test_utils::random::{make_seedable_rng, Seed};
use tx_verifier::transaction_verifier::{
    config::TransactionVerifierConfig, error::ConnectTransactionError, flush::flush_to_storage,
    storage::TransactionVerifierStorageRef, BlockTransactableRef, BlockTransactableWithIndexRef,
    Fee, Subsidy, TransactionVerifier, TransactionVerifierDelta,
};
use utils::tap_error_log::LogError;
use utxo::UtxosView;

///
/// This strategy operates on transactions with 2 verifiers.
/// It can represented as a finite state machine that for every transaction randomly changes state as follows:
///
/// ```text
///                  _______flush______
///                 |                  |
///                 V                  |
/// TransactionVerifier ---derive--> TransactionVerifier
///  |              ^                 |              ^
///  |              |                 |              |
///  |__process tx__|                 |__process tx__|
/// ```
///
pub struct RandomizedTransactionVerificationStrategy {
    rng: RefCell<Box<dyn RngCore + Send>>,
}

impl RandomizedTransactionVerificationStrategy {
    pub fn new(seed: Seed) -> Self {
        Self {
            rng: RefCell::new(Box::new(make_seedable_rng(seed))),
        }
    }
}

impl TransactionVerificationStrategy for RandomizedTransactionVerificationStrategy {
    fn connect_block<'a, H, S, M, U>(
        &self,
        tx_verifier_maker: M,
        block_index_handle: &'a H,
        storage_backend: &'a S,
        chain_config: &'a ChainConfig,
        verifier_config: TransactionVerifierConfig,
        block_index: &'a BlockIndex,
        block: &WithId<Block>,
    ) -> Result<TransactionVerifier<'a, S, U>, BlockError>
    where
        H: BlockIndexHandle,
        S: TransactionVerifierStorageRef,
        U: UtxosView,
        M: Fn(&'a S, &'a ChainConfig, TransactionVerifierConfig) -> TransactionVerifier<'a, S, U>,
    {
        // The comparison for timelock is done with median_time_past based on BIP-113, i.e., the median time instead of the block timestamp
        let median_time_past =
            calculate_median_time_past(block_index_handle, &block.prev_block_id());

        let (mut tx_verifier, total_fees) = self
            .connect_with_base(
                tx_verifier_maker,
                storage_backend,
                chain_config,
                verifier_config,
                block_index,
                block,
                &median_time_past,
            )
            .log_err()?;

        let block_subsidy = chain_config.block_subsidy_at_height(&block_index.block_height());
        tx_verifier
            .check_block_reward(block, Fee(total_fees), Subsidy(block_subsidy))
            .log_err()?;

        tx_verifier.set_best_block(block.get_id().into());

        Ok(tx_verifier)
    }

    fn disconnect_block<'a, S, M, U>(
        &self,
        tx_verifier_maker: M,
        storage_backend: &'a S,
        chain_config: &'a ChainConfig,
        verifier_config: TransactionVerifierConfig,
        block: &WithId<Block>,
    ) -> Result<TransactionVerifier<'a, S, U>, BlockError>
    where
        S: TransactionVerifierStorageRef,
        U: UtxosView,
        M: Fn(&'a S, &'a ChainConfig, TransactionVerifierConfig) -> TransactionVerifier<'a, S, U>,
    {
        let mut tx_verifier = self.disconnect_with_base(
            tx_verifier_maker,
            storage_backend,
            chain_config,
            verifier_config,
            block,
        )?;

        tx_verifier.set_best_block(block.prev_block_id());

        Ok(tx_verifier)
    }
}

impl RandomizedTransactionVerificationStrategy {
    #[allow(clippy::too_many_arguments)]
    fn connect_with_base<'a, S, M, U>(
        &self,
        tx_verifier_maker: M,
        storage_backend: &'a S,
        chain_config: &'a ChainConfig,
        verifier_config: TransactionVerifierConfig,
        block_index: &'a BlockIndex,
        block: &WithId<Block>,
        median_time_past: &BlockTimestamp,
    ) -> Result<(TransactionVerifier<'a, S, U>, Amount), ConnectTransactionError>
    where
        S: TransactionVerifierStorageRef,
        U: UtxosView,
        M: Fn(&'a S, &'a ChainConfig, TransactionVerifierConfig) -> TransactionVerifier<'a, S, U>,
    {
        let mut tx_indices = construct_tx_indices(&verifier_config, block)?;
        let block_reward_tx_index = construct_reward_tx_indices(&verifier_config, block)?;

        let mut tx_verifier = tx_verifier_maker(storage_backend, chain_config, verifier_config);

        let reward_fees = tx_verifier
            .connect_transactable(
                block_index,
                BlockTransactableWithIndexRef::BlockReward(block, block_reward_tx_index),
                median_time_past,
            )
            .log_err()?;
        debug_assert!(reward_fees.is_none());

        let mut total_fee = Amount::ZERO;
        let mut tx_num = 0usize;
        while tx_num < block.transactions().len() {
            if self.rng.borrow_mut().gen::<bool>() {
                // derive a new cache
                let (consumed_cache, fee, new_tx_index) = self.connect_with_derived(
                    &tx_verifier,
                    block,
                    block_index,
                    median_time_past,
                    &mut tx_indices,
                    tx_num,
                )?;

                total_fee = (total_fee + fee).ok_or_else(|| {
                    ConnectTransactionError::FailedToAddAllFeesOfBlock(block.get_id())
                })?;

                flush_to_storage(&mut tx_verifier, consumed_cache)
                    .map_err(ConnectTransactionError::from)?;
                tx_num = new_tx_index;
            } else {
                // connect transactable using current verifier
                tx_verifier.connect_transactable(
                    block_index,
                    BlockTransactableWithIndexRef::Transaction(
                        block,
                        tx_num,
                        take_tx_index(&mut tx_indices),
                    ),
                    median_time_past,
                )?;
                tx_num += 1;
            }
        }
        Ok((tx_verifier, total_fee))
    }

    fn connect_with_derived<'a, S, U>(
        &self,
        base_tx_verifier: &TransactionVerifier<'a, S, U>,
        block: &WithId<Block>,
        block_index: &'a BlockIndex,
        median_time_past: &BlockTimestamp,
        tx_indices: &mut Option<VecDeque<TxMainChainIndex>>,
        mut tx_num: usize,
    ) -> Result<(TransactionVerifierDelta, Amount, usize), ConnectTransactionError>
    where
        U: UtxosView,
        S: TransactionVerifierStorageRef,
    {
        let mut tx_verifier = base_tx_verifier.derive_child();
        let mut total_fee = Amount::ZERO;
        while tx_num < block.transactions().len() {
            if self.rng.borrow_mut().gen::<bool>() {
                // break the loop, which effectively would flush current state to the parent
                break;
            } else {
                // connect transactable using current verifier
                let fee = tx_verifier.connect_transactable(
                    block_index,
                    BlockTransactableWithIndexRef::Transaction(
                        block,
                        tx_num,
                        take_tx_index(tx_indices),
                    ),
                    median_time_past,
                )?;

                total_fee = (total_fee + fee.expect("some").0).ok_or_else(|| {
                    ConnectTransactionError::FailedToAddAllFeesOfBlock(block.get_id())
                })?;
                tx_num += 1;
            }
        }
        let cache = tx_verifier.consume()?;
        Ok((cache, total_fee, tx_num))
    }

    fn disconnect_with_base<'a, S, M, U>(
        &self,
        tx_verifier_maker: M,
        storage_backend: &'a S,
        chain_config: &'a ChainConfig,
        verifier_config: TransactionVerifierConfig,
        block: &WithId<Block>,
    ) -> Result<TransactionVerifier<'a, S, U>, ConnectTransactionError>
    where
        S: TransactionVerifierStorageRef,
        U: UtxosView,
        M: Fn(&'a S, &'a ChainConfig, TransactionVerifierConfig) -> TransactionVerifier<'a, S, U>,
    {
        let mut tx_verifier = tx_verifier_maker(storage_backend, chain_config, verifier_config);
        let mut tx_num = i32::try_from(block.transactions().len()).unwrap() - 1;
        while tx_num >= 0 {
            if self.rng.borrow_mut().gen::<bool>() {
                // derive a new cache
                let (consumed_cache, new_tx_index) =
                    self.disconnect_with_derived(&tx_verifier, block, tx_num)?;

                flush_to_storage(&mut tx_verifier, consumed_cache)
                    .map_err(ConnectTransactionError::from)?;
                tx_num = new_tx_index;
            } else {
                // disconnect transactable using current verifier
                tx_verifier.disconnect_transactable(BlockTransactableRef::Transaction(
                    block,
                    tx_num as usize,
                ))?;
                tx_num -= 1;
            }
        }

        tx_verifier
            .disconnect_transactable(BlockTransactableRef::BlockReward(block))
            .log_err()?;

        Ok(tx_verifier)
    }

    fn disconnect_with_derived<'a, S, U>(
        &self,
        base_tx_verifier: &TransactionVerifier<'a, S, U>,
        block: &WithId<Block>,
        mut tx_num: i32,
    ) -> Result<(TransactionVerifierDelta, i32), ConnectTransactionError>
    where
        U: UtxosView,
        S: TransactionVerifierStorageRef,
    {
        let mut tx_verifier = base_tx_verifier.derive_child();
        while tx_num >= 0 {
            if self.rng.borrow_mut().gen::<bool>() {
                // break the loop, which effectively would flush current state to the parent
                break;
            } else {
                // disconnect transactable using current verifier
                tx_verifier.disconnect_transactable(BlockTransactableRef::Transaction(
                    block,
                    tx_num as usize,
                ))?;
                tx_num -= 1;
            }
        }
        let cache = tx_verifier.consume()?;
        Ok((cache, tx_num))
    }
}
