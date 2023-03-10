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

use super::TransactionVerificationStrategy;
use crate::{
    calculate_median_time_past,
    tx_verification_strategy_utils::{
        construct_reward_tx_indices, construct_tx_indices, take_front_tx_index,
    },
    BlockError, TransactionVerifierMakerFn,
};
use chainstate_types::{BlockIndex, BlockIndexHandle};
use common::{
    chain::{Block, ChainConfig},
    primitives::{id::WithId, Amount, Idable},
};
use pos_accounting::PoSAccountingView;
use tx_verifier::transaction_verifier::{
    config::TransactionVerifierConfig, error::ConnectTransactionError,
    storage::TransactionVerifierStorageRef, BlockTransactableRef, BlockTransactableWithIndexRef,
    Fee, Subsidy, TransactionVerifier,
};
use utils::tap_error_log::LogError;
use utxo::UtxosView;

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
    fn connect_block<C, H, S, M, U, A>(
        &self,
        tx_verifier_maker: M,
        block_index_handle: &H,
        storage_backend: S,
        chain_config: C,
        verifier_config: TransactionVerifierConfig,
        block_index: &BlockIndex,
        block: &WithId<Block>,
    ) -> Result<TransactionVerifier<C, S, U, A>, BlockError>
    where
        C: AsRef<ChainConfig>,
        H: BlockIndexHandle,
        S: TransactionVerifierStorageRef,
        U: UtxosView,
        A: PoSAccountingView,
        M: TransactionVerifierMakerFn<C, S, U, A>,
    {
        // The comparison for timelock is done with median_time_past based on BIP-113, i.e., the median time instead of the block timestamp
        let median_time_past =
            calculate_median_time_past(block_index_handle, &block.prev_block_id());

        let block_subsidy =
            chain_config.as_ref().block_subsidy_at_height(&block_index.block_height());

        let mut tx_indices = construct_tx_indices(&verifier_config, block)?;
        let block_reward_tx_index = construct_reward_tx_indices(&verifier_config, block)?;

        let mut tx_verifier = tx_verifier_maker(storage_backend, chain_config, verifier_config);

        let total_fees = block
            .transactions()
            .iter()
            .enumerate()
            .try_fold(Amount::from_atoms(0), |total, (tx_num, _)| {
                let fee = tx_verifier
                    .connect_transactable(
                        block_index,
                        BlockTransactableWithIndexRef::Transaction(
                            block,
                            tx_num,
                            take_front_tx_index(&mut tx_indices),
                        ),
                        &median_time_past,
                    )
                    .log_err()?;
                (total + fee.expect("connect tx should return fees").0).ok_or_else(|| {
                    ConnectTransactionError::FailedToAddAllFeesOfBlock(block.get_id())
                })
            })
            .log_err()?;

        // TODO: reconsider the order of connect txs and check block reward.
        //       Ideally we want to check everything before mutating the state.
        //       Previously check block reward was done before the reward was connected, but
        //       the connection of reward spends the output preventing proper validation.
        tx_verifier
            .check_block_reward(block, Fee(total_fees), Subsidy(block_subsidy))
            .log_err()?;

        let reward_fees = tx_verifier
            .connect_transactable(
                block_index,
                BlockTransactableWithIndexRef::BlockReward(block, block_reward_tx_index),
                &median_time_past,
            )
            .log_err()?;
        debug_assert!(reward_fees.is_none());

        tx_verifier.set_best_block(block.get_id().into());

        Ok(tx_verifier)
    }

    fn disconnect_block<C, S, M, U, A>(
        &self,
        tx_verifier_maker: M,
        storage_backend: S,
        chain_config: C,
        verifier_config: TransactionVerifierConfig,
        block: &WithId<Block>,
    ) -> Result<TransactionVerifier<C, S, U, A>, BlockError>
    where
        C: AsRef<ChainConfig>,
        S: TransactionVerifierStorageRef,
        U: UtxosView,
        A: PoSAccountingView,
        M: TransactionVerifierMakerFn<C, S, U, A>,
    {
        let mut tx_verifier = tx_verifier_maker(storage_backend, chain_config, verifier_config);

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

        tx_verifier.set_best_block(block.prev_block_id());

        Ok(tx_verifier)
    }
}
