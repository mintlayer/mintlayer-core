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

use std::cell::RefCell;

use super::TransactionVerificationStrategy;
use crate::{calculate_median_time_past, BlockError};
use chainstate_types::{BlockIndex, BlockIndexHandle};
use common::{
    chain::{block::timestamp::BlockTimestamp, Block, ChainConfig},
    primitives::{id::WithId, Amount, Idable},
};
use crypto::random::{Rng, RngCore};
use test_utils::random::{make_seedable_rng, Seed};
use tx_verifier::transaction_verifier::{
    error::ConnectTransactionError, flush::flush_to_storage,
    storage::TransactionVerifierStorageRef, BlockTransactableRef, Fee, Subsidy,
    TransactionVerifier,
};
use utils::tap_error_log::LogError;

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
    fn connect_block<'a, H, S, M>(
        &self,
        tx_verifier_maker: M,
        block_index_handle: &'a H,
        storage_backend: &'a S,
        chain_config: &'a ChainConfig,
        block_index: &'a BlockIndex,
        block: &WithId<Block>,
    ) -> Result<TransactionVerifier<'a, S>, BlockError>
    where
        H: BlockIndexHandle,
        S: TransactionVerifierStorageRef,
        M: Fn(&'a S, &'a ChainConfig) -> TransactionVerifier<'a, S>,
    {
        // The comparison for timelock is done with median_time_past based on BIP-113, i.e., the median time instead of the block timestamp
        let median_time_past =
            calculate_median_time_past(block_index_handle, &block.prev_block_id());

        let mut base_tx_verifier = tx_verifier_maker(storage_backend, chain_config);

        // connect block reward
        let reward_fees = if self.rng.borrow_mut().gen::<bool>() {
            base_tx_verifier
                .connect_transactable(
                    block_index,
                    BlockTransactableRef::BlockReward(block),
                    &block_index.block_height(),
                    &median_time_past,
                )
                .log_err()?
        } else {
            let mut tx_verifier = base_tx_verifier.derive_child();
            let reward_fees = tx_verifier
                .connect_transactable(
                    block_index,
                    BlockTransactableRef::BlockReward(block),
                    &block_index.block_height(),
                    &median_time_past,
                )
                .log_err()?;
            let consumed_cache = tx_verifier.consume()?;
            flush_to_storage(&mut base_tx_verifier, consumed_cache)?;
            reward_fees
        };
        debug_assert!(reward_fees.is_none());

        // connect transactions recursively
        let total_fees = if !block.transactions().is_empty() {
            self.connect_transactable_step(
                &mut base_tx_verifier,
                block,
                block_index,
                &median_time_past,
                0,
                Amount::ZERO,
            )?
        } else {
            Amount::ZERO
        };

        let block_subsidy = chain_config.block_subsidy_at_height(&block_index.block_height());
        base_tx_verifier
            .check_block_reward(block, Fee(total_fees), Subsidy(block_subsidy))
            .log_err()?;

        base_tx_verifier.set_best_block(block.get_id().into());

        Ok(base_tx_verifier)
    }

    fn disconnect_block<'a, S, M>(
        &self,
        tx_verifier_maker: M,
        storage_backend: &'a S,
        chain_config: &'a ChainConfig,
        block: &WithId<Block>,
    ) -> Result<TransactionVerifier<'a, S>, BlockError>
    where
        S: TransactionVerifierStorageRef,
        M: Fn(&'a S, &'a ChainConfig) -> TransactionVerifier<'a, S>,
    {
        let mut base_tx_verifier = tx_verifier_maker(storage_backend, chain_config);

        // disconnect transactions recursively
        if !block.transactions().is_empty() {
            self.disconnect_transactable_step(
                &mut base_tx_verifier,
                block,
                Some(block.transactions().len() - 1),
            )?;
        }

        // disconnect block reward
        if self.rng.borrow_mut().gen::<bool>() {
            let mut tx_verifier = base_tx_verifier.derive_child();
            tx_verifier
                .disconnect_transactable(BlockTransactableRef::BlockReward(block))
                .log_err()?;
            let consumed_cache = tx_verifier.consume()?;
            flush_to_storage(&mut base_tx_verifier, consumed_cache)?;
        } else {
            base_tx_verifier
                .disconnect_transactable(BlockTransactableRef::BlockReward(block))
                .log_err()?;
        }

        base_tx_verifier.set_best_block(block.prev_block_id());

        Ok(base_tx_verifier)
    }
}

impl RandomizedTransactionVerificationStrategy {
    fn connect_transactable_step<'a, S: TransactionVerifierStorageRef>(
        &self,
        base_tx_verifier: &mut TransactionVerifier<S>,
        block: &WithId<Block>,
        block_index: &'a BlockIndex,
        median_time_past: &BlockTimestamp,
        current_tx_index: usize,
        current_fees: Amount,
    ) -> Result<Amount, ConnectTransactionError> {
        if current_tx_index == block.transactions().len() {
            return Ok(current_fees);
        }

        // on every step we either use current verifier or derive a new one
        if self.rng.borrow_mut().gen::<bool>() {
            let fee = base_tx_verifier
                .connect_transactable(
                    block_index,
                    BlockTransactableRef::Transaction(block, current_tx_index),
                    &block_index.block_height(),
                    median_time_past,
                )
                .log_err()?;

            let current_fees = self.connect_transactable_step(
                base_tx_verifier,
                block,
                block_index,
                median_time_past,
                current_tx_index + 1,
                current_fees,
            )?;

            (current_fees + fee.expect("connect tx should return fees").0)
                .ok_or_else(|| ConnectTransactionError::FailedToAddAllFeesOfBlock(block.get_id()))
        } else {
            let mut new_tx_verifier = base_tx_verifier.derive_child();
            let current_fees = self.connect_transactable_step(
                &mut new_tx_verifier,
                block,
                block_index,
                median_time_past,
                current_tx_index + 1,
                current_fees,
            )?;

            let consumed_cache = new_tx_verifier.consume()?;
            flush_to_storage(base_tx_verifier, consumed_cache)?;
            Ok(current_fees)
        }
    }

    fn disconnect_transactable_step<S: TransactionVerifierStorageRef>(
        &self,
        base_tx_verifier: &mut TransactionVerifier<S>,
        block: &WithId<Block>,
        current_tx_index: Option<usize>,
    ) -> Result<(), ConnectTransactionError> {
        if current_tx_index.is_none() {
            return Ok(());
        }

        let current_tx_index = current_tx_index.expect("tx index should be some");
        let next_tx_index = if current_tx_index == 0 {
            None
        } else {
            Some(current_tx_index - 1)
        };

        // on every step we either use current verifier or derive a new one
        if self.rng.borrow_mut().gen::<bool>() {
            base_tx_verifier
                .disconnect_transactable(BlockTransactableRef::Transaction(block, current_tx_index))
                .log_err()?;
            self.disconnect_transactable_step(base_tx_verifier, block, next_tx_index)?;
        } else {
            let mut new_tx_verifier = base_tx_verifier.derive_child();
            self.disconnect_transactable_step(&mut new_tx_verifier, block, next_tx_index)?;

            let consumed_cache = new_tx_verifier.consume()?;
            flush_to_storage(base_tx_verifier, consumed_cache)?;
        }

        Ok(())
    }
}
