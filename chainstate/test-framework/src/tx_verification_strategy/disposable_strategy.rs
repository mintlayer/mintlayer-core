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
    TransactionVerificationStrategy, TransactionVerifierMakerFn, TransactionVerifierStorageError,
};
use chainstate_types::BlockIndex;
use common::{
    chain::{block::timestamp::BlockTimestamp, Block, ChainConfig},
    primitives::{id::WithId, Idable},
};
use constraints_value_accumulator::AccumulatedFee;
use orders_accounting::OrdersAccountingView;
use pos_accounting::PoSAccountingView;
use tokens_accounting::TokensAccountingView;
use tx_verifier::{
    transaction_verifier::{
        error::ConnectTransactionError, flush::flush_to_storage,
        storage::TransactionVerifierStorageRef, TransactionSourceForConnect, TransactionVerifier,
    },
    TransactionSource,
};
use utils::{shallow_clone::ShallowClone, tap_log::TapLog};
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
    fn connect_block<C, S, M, U, A, T, O>(
        &self,
        tx_verifier_maker: M,
        storage_backend: S,
        chain_config: C,
        block_index: &BlockIndex,
        block: &WithId<Block>,
        median_time_past: BlockTimestamp,
    ) -> Result<TransactionVerifier<C, S, U, A, T, O>, ConnectTransactionError>
    where
        C: AsRef<ChainConfig> + ShallowClone,
        S: TransactionVerifierStorageRef<Error = TransactionVerifierStorageError>,
        U: UtxosView,
        A: PoSAccountingView,
        T: TokensAccountingView,
        O: OrdersAccountingView,
        M: TransactionVerifierMakerFn<C, S, U, A, T, O>,
        <S as utxo::UtxosStorageRead>::Error: From<U::Error>,
    {
        let mut base_tx_verifier = tx_verifier_maker(storage_backend, chain_config.shallow_clone());

        let total_fees = block
            .transactions()
            .iter()
            .try_fold(AccumulatedFee::new(), |total, tx| {
                let mut tx_verifier = base_tx_verifier.derive_child();
                let fee = tx_verifier
                    .connect_transaction(
                        &TransactionSourceForConnect::Chain {
                            new_block_index: block_index,
                        },
                        tx,
                        &median_time_past,
                    )
                    .log_err()?;
                let consumed_cache = tx_verifier.consume()?;
                flush_to_storage(&mut base_tx_verifier, consumed_cache).log_err()?;

                total
                    .combine(fee)
                    .map_err(|_| ConnectTransactionError::FailedToAddAllFeesOfBlock(block.get_id()))
            })
            .log_err()?;
        let total_fees = total_fees
            .map_into_block_fees(chain_config.as_ref(), block_index.block_height())
            .map_err(|err| {
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    err,
                    block.get_id().into(),
                )
            })?;

        base_tx_verifier
            .check_block_reward(block, total_fees, block_index.block_height())
            .log_err()?;

        base_tx_verifier
            .connect_block_reward(
                block_index,
                block.block_reward_transactable(),
                total_fees,
                median_time_past,
            )
            .log_err()?;

        base_tx_verifier.set_best_block(block.get_id().into());

        Ok(base_tx_verifier)
    }

    fn disconnect_block<C, S, M, U, A, T, O>(
        &self,
        tx_verifier_maker: M,
        storage_backend: S,
        chain_config: C,
        block: &WithId<Block>,
    ) -> Result<TransactionVerifier<C, S, U, A, T, O>, ConnectTransactionError>
    where
        C: AsRef<ChainConfig>,
        S: TransactionVerifierStorageRef<Error = TransactionVerifierStorageError>,
        U: UtxosView,
        A: PoSAccountingView,
        T: TokensAccountingView,
        O: OrdersAccountingView,
        M: TransactionVerifierMakerFn<C, S, U, A, T, O>,
        <S as utxo::UtxosStorageRead>::Error: From<U::Error>,
    {
        let mut base_tx_verifier = tx_verifier_maker(storage_backend, chain_config);

        let mut tx_verifier = base_tx_verifier.derive_child();
        tx_verifier.disconnect_block_reward(block).log_err()?;
        let consumed_cache = tx_verifier.consume()?;
        flush_to_storage(&mut base_tx_verifier, consumed_cache)?;

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

        base_tx_verifier.set_best_block(block.prev_block_id());

        Ok(base_tx_verifier)
    }
}
