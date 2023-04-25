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

use chainstate::{
    calculate_median_time_past,
    tx_verification_strategy_utils::{
        construct_reward_tx_indices, construct_tx_indices, take_front_tx_index,
    },
    BlockError, TransactionVerificationStrategy, TransactionVerifierMakerFn,
    TransactionVerifierStorageError,
};
use chainstate_types::{BlockIndex, BlockIndexHandle};
use common::{
    chain::{Block, ChainConfig},
    primitives::{id::WithId, Amount, Idable},
};
use pos_accounting::PoSAccountingView;
use tx_verifier::{
    transaction_verifier::{
        config::TransactionVerifierConfig, error::ConnectTransactionError, flush::flush_to_storage,
        storage::TransactionVerifierStorageRef, Fee, Subsidy, TransactionSourceForConnect,
        TransactionVerifier,
    },
    TransactionSource,
};
use utils::tap_error_log::LogError;
use utxo::UtxosView;

/// Strategy that creates separate instances of TransactionVerifier on every tx, flushing the
/// result to a single TransactionVerifier that is returned from the connect/disconnect functions.
/// For now this is only used for testing purposes.
pub struct DisposableTransactionVerificationStrategy {}

impl DisposableTransactionVerificationStrategy {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for DisposableTransactionVerificationStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionVerificationStrategy for DisposableTransactionVerificationStrategy {
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
        S: TransactionVerifierStorageRef<Error = TransactionVerifierStorageError>,
        U: UtxosView,
        A: PoSAccountingView,
        M: TransactionVerifierMakerFn<C, S, U, A>,
        <S as utxo::UtxosStorageRead>::Error: From<U::Error>,
    {
        // The comparison for timelock is done with median_time_past based on BIP-113, i.e., the median time instead of the block timestamp
        let median_time_past =
            calculate_median_time_past(block_index_handle, &block.prev_block_id());
        let block_subsidy =
            chain_config.as_ref().block_subsidy_at_height(&block_index.block_height());

        let mut tx_indices = construct_tx_indices(&verifier_config, block)?;
        let block_reward_tx_index = construct_reward_tx_indices(&verifier_config, block)?;

        let mut base_tx_verifier =
            tx_verifier_maker(storage_backend, chain_config, verifier_config);

        let total_fees = block
            .transactions()
            .iter()
            .try_fold(Amount::from_atoms(0), |total, tx| {
                let mut tx_verifier = base_tx_verifier.derive_child();
                let fee = tx_verifier
                    .connect_transaction(
                        &TransactionSourceForConnect::Chain {
                            new_block_index: block_index,
                        },
                        &tx,
                        &median_time_past,
                        take_front_tx_index(&mut tx_indices),
                    )
                    .map_err(BlockError::StateUpdateFailed)
                    .log_err()?;
                let consumed_cache = tx_verifier.consume()?;
                flush_to_storage(&mut base_tx_verifier, consumed_cache)
                    .map_err(BlockError::TransactionVerifierError)
                    .log_err()?;

                (total + fee.0).ok_or_else(|| {
                    BlockError::StateUpdateFailed(
                        ConnectTransactionError::FailedToAddAllFeesOfBlock(block.get_id()),
                    )
                })
            })
            .log_err()?;

        base_tx_verifier
            .check_block_reward(block, Fee(total_fees), Subsidy(block_subsidy))
            .log_err()?;

        base_tx_verifier
            .connect_block_reward(
                block_index,
                block.block_reward_transactable(),
                Fee(total_fees),
                block_reward_tx_index,
            )
            .log_err()?;

        base_tx_verifier.set_best_block(block.get_id().into());

        Ok(base_tx_verifier)
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
        S: TransactionVerifierStorageRef<Error = TransactionVerifierStorageError>,
        U: UtxosView,
        A: PoSAccountingView,
        M: TransactionVerifierMakerFn<C, S, U, A>,
        <S as utxo::UtxosStorageRead>::Error: From<U::Error>,
    {
        let mut base_tx_verifier =
            tx_verifier_maker(storage_backend, chain_config, verifier_config);

        block
            .transactions()
            .iter()
            .rev()
            .try_for_each(|tx| {
                let mut tx_verifier = base_tx_verifier.derive_child();

                tx_verifier
                    .disconnect_transaction(&TransactionSource::Chain(block.get_id()), tx)
                    .log_err()?;

                let consumed_cache = tx_verifier.consume()?;
                flush_to_storage(&mut base_tx_verifier, consumed_cache)
                    .map_err(BlockError::TransactionVerifierError)
            })
            .log_err()?;

        let mut tx_verifier = base_tx_verifier.derive_child();
        tx_verifier.disconnect_block_reward(block).log_err()?;
        let consumed_cache = tx_verifier.consume()?;
        flush_to_storage(&mut base_tx_verifier, consumed_cache)?;

        base_tx_verifier.set_best_block(block.prev_block_id());

        Ok(base_tx_verifier)
    }
}
