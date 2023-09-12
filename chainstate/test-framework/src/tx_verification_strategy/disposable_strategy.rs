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
    tx_verification_strategy_utils::{
        construct_reward_tx_indices, construct_tx_indices, take_front_tx_index,
    },
    TransactionVerificationStrategy, TransactionVerifierMakerFn, TransactionVerifierStorageError,
};
use chainstate_types::BlockIndex;
use common::{
    chain::{block::timestamp::BlockTimestamp, Block, ChainConfig},
    primitives::{id::WithId, Amount, Idable},
};
use pos_accounting::PoSAccountingView;
use tokens_accounting::TokensAccountingView;
use tx_verifier::{
    transaction_verifier::{
        config::TransactionVerifierConfig, error::ConnectTransactionError, flush::flush_to_storage,
        storage::TransactionVerifierStorageRef, Fee, TransactionSourceForConnect,
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
    fn connect_block<C, S, M, U, A, T>(
        &self,
        tx_verifier_maker: M,
        storage_backend: S,
        chain_config: C,
        verifier_config: TransactionVerifierConfig,
        block_index: &BlockIndex,
        block: &WithId<Block>,
        median_time_past: BlockTimestamp,
    ) -> Result<TransactionVerifier<C, S, U, A, T>, ConnectTransactionError>
    where
        C: AsRef<ChainConfig>,
        S: TransactionVerifierStorageRef<Error = TransactionVerifierStorageError>,
        U: UtxosView,
        A: PoSAccountingView,
        T: TokensAccountingView,
        M: TransactionVerifierMakerFn<C, S, U, A, T>,
        <S as utxo::UtxosStorageRead>::Error: From<U::Error>,
    {
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
                        tx,
                        &median_time_past,
                        take_front_tx_index(&mut tx_indices),
                    )
                    .log_err()?;
                let consumed_cache = tx_verifier.consume()?;
                flush_to_storage(&mut base_tx_verifier, consumed_cache).log_err()?;

                (total + fee.0).ok_or_else(|| {
                    ConnectTransactionError::FailedToAddAllFeesOfBlock(block.get_id())
                })
            })
            .log_err()?;

        base_tx_verifier
            .check_block_reward(block, Fee(total_fees), block_index.block_height())
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

    fn disconnect_block<C, S, M, U, A, T>(
        &self,
        tx_verifier_maker: M,
        storage_backend: S,
        chain_config: C,
        verifier_config: TransactionVerifierConfig,
        block: &WithId<Block>,
    ) -> Result<TransactionVerifier<C, S, U, A, T>, ConnectTransactionError>
    where
        C: AsRef<ChainConfig>,
        S: TransactionVerifierStorageRef<Error = TransactionVerifierStorageError>,
        U: UtxosView,
        A: PoSAccountingView,
        T: TokensAccountingView,
        M: TransactionVerifierMakerFn<C, S, U, A, T>,
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
                    .map_err(ConnectTransactionError::TransactionVerifierError)
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
