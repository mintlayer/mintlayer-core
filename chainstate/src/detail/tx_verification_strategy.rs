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

use chainstate_types::{BlockIndex, BlockIndexHandle};
use common::{
    chain::{Block, ChainConfig, GenBlock},
    primitives::{id::WithId, Amount, BlockHeight, Id, Idable},
};
use tx_verifier::transaction_verifier::{
    error::ConnectTransactionError, storage::TransactionVerifierStorageRef, BlockTransactableRef,
    Fee, Subsidy, TransactionVerifier,
};
use utils::tap_error_log::LogError;

use crate::{calculate_median_time_past, BlockError};

/// A trait that specifies how a block will be verified
pub trait TransactionVerificationStrategy: Sized + Send {
    fn connect_block<'a, H: BlockIndexHandle, S: TransactionVerifierStorageRef>(
        &self,
        block_index_handle: &'a H,
        storage_backend: &'a S,
        chain_config: &'a ChainConfig,
        block_index: &'a BlockIndex,
        block: &WithId<Block>,
        spend_height: &BlockHeight,
    ) -> Result<TransactionVerifier<'a, S>, BlockError>;

    fn disconnect_block<'a, S: TransactionVerifierStorageRef>(
        &self,
        storage_backend: &'a S,
        chain_config: &'a ChainConfig,
        block: &WithId<Block>,
        prev_block_id: Id<GenBlock>,
    ) -> Result<TransactionVerifier<'a, S>, BlockError>;
}

pub struct DefaultTransactionVerificationStrategy {}

impl DefaultTransactionVerificationStrategy {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for DefaultTransactionVerificationStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionVerificationStrategy for DefaultTransactionVerificationStrategy {
    fn connect_block<'a, H: BlockIndexHandle, S: TransactionVerifierStorageRef>(
        &self,
        block_index_handle: &'a H,
        storage_backend: &'a S,
        chain_config: &'a ChainConfig,
        block_index: &'a BlockIndex,
        block: &WithId<Block>,
        spend_height: &BlockHeight,
    ) -> Result<TransactionVerifier<'a, S>, BlockError> {
        // The comparison for timelock is done with median_time_past based on BIP-113, i.e., the median time instead of the block timestamp
        let median_time_past =
            calculate_median_time_past(block_index_handle, &block.prev_block_id());

        let mut tx_verifier = TransactionVerifier::new(storage_backend, chain_config);

        let reward_fees = tx_verifier
            .connect_transactable(
                block_index,
                BlockTransactableRef::BlockReward(block),
                spend_height,
                &median_time_past,
            )
            .log_err()?;
        debug_assert!(reward_fees.is_none());

        let total_fees = block
            .transactions()
            .iter()
            .enumerate()
            .try_fold(Amount::from_atoms(0), |total, (tx_num, _)| {
                let fee = tx_verifier
                    .connect_transactable(
                        block_index,
                        BlockTransactableRef::Transaction(block, tx_num),
                        spend_height,
                        &median_time_past,
                    )
                    .log_err()?;
                (total + fee.expect("connect tx should return fees").0).ok_or_else(|| {
                    ConnectTransactionError::FailedToAddAllFeesOfBlock(block.get_id())
                })
            })
            .log_err()?;

        let block_subsidy = chain_config.block_subsidy_at_height(spend_height);
        tx_verifier
            .check_block_reward(block, Fee(total_fees), Subsidy(block_subsidy))
            .log_err()?;

        tx_verifier.set_best_block(block.get_id().into());

        Ok(tx_verifier)
    }

    fn disconnect_block<'a, S: TransactionVerifierStorageRef>(
        &self,
        storage_backend: &'a S,
        chain_config: &'a ChainConfig,
        block: &WithId<Block>,
        prev_block_id: Id<GenBlock>,
    ) -> Result<TransactionVerifier<'a, S>, BlockError> {
        let mut tx_verifier = TransactionVerifier::new(storage_backend, chain_config);

        // TODO: add a test that checks the order in which txs are disconnected
        block
            .transactions()
            .iter()
            .enumerate()
            .rev()
            .try_for_each(|(tx_num, _)| {
                tx_verifier
                    .disconnect_transactable(BlockTransactableRef::Transaction(block, tx_num))
            })
            .log_err()?;
        tx_verifier
            .disconnect_transactable(BlockTransactableRef::BlockReward(block))
            .log_err()?;

        tx_verifier.set_best_block(prev_block_id);

        Ok(tx_verifier)
    }
}
