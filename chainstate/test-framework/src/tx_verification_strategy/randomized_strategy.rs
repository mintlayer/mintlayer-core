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

use std::collections::VecDeque;

use chainstate::{
    tx_verification_strategy_utils::{
        construct_reward_tx_indices, construct_tx_indices, take_front_tx_index,
    },
    TransactionVerificationStrategy, TransactionVerifierMakerFn, TransactionVerifierStorageError,
};
use chainstate_types::BlockIndex;
use common::{
    chain::{block::timestamp::BlockTimestamp, Block, ChainConfig, TxMainChainIndex},
    primitives::{id::WithId, Amount, Idable},
};
use crypto::random::{Rng, RngCore};
use pos_accounting::PoSAccountingView;
use test_utils::random::{make_seedable_rng, Seed};
use tokens_accounting::TokensAccountingView;
use tx_verifier::{
    transaction_verifier::{
        config::TransactionVerifierConfig, error::ConnectTransactionError, flush::flush_to_storage,
        storage::TransactionVerifierStorageRef, Fee, TransactionSourceForConnect,
        TransactionVerifier, TransactionVerifierDelta,
    },
    TransactionSource,
};
use utils::tap_error_log::LogError;
use utxo::UtxosView;

///
/// This strategy operates on transactions with 2 verifiers.
/// It can be represented as a finite state machine that for every transaction randomly changes state as follows:
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
    rng: std::sync::Mutex<Box<dyn RngCore + Send>>,
}

impl RandomizedTransactionVerificationStrategy {
    pub fn new(seed: Seed) -> Self {
        Self {
            rng: std::sync::Mutex::new(Box::new(make_seedable_rng(seed))),
        }
    }
}

impl TransactionVerificationStrategy for RandomizedTransactionVerificationStrategy {
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
        let mut tx_verifier = self
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

        tx_verifier.set_best_block(block.get_id().into());

        Ok(tx_verifier)
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
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn connect_with_base<C: AsRef<ChainConfig>, S, M, U, A, T>(
        &self,
        tx_verifier_maker: M,
        storage_backend: S,
        chain_config: C,
        verifier_config: TransactionVerifierConfig,
        block_index: &BlockIndex,
        block: &WithId<Block>,
        median_time_past: &BlockTimestamp,
    ) -> Result<TransactionVerifier<C, S, U, A, T>, ConnectTransactionError>
    where
        S: TransactionVerifierStorageRef<Error = TransactionVerifierStorageError>,
        U: UtxosView,
        A: PoSAccountingView,
        T: TokensAccountingView,
        M: TransactionVerifierMakerFn<C, S, U, A, T>,
        <S as utxo::UtxosStorageRead>::Error: From<U::Error>,
    {
        let mut tx_indices = construct_tx_indices(&verifier_config, block)?;
        let block_reward_tx_index = construct_reward_tx_indices(&verifier_config, block)?;

        let mut tx_verifier = tx_verifier_maker(storage_backend, chain_config, verifier_config);

        let mut total_fees = Amount::ZERO;
        let mut tx_num = 0usize;
        while tx_num < block.transactions().len() {
            if self.rng.lock().unwrap().gen::<bool>() {
                // derive a new cache
                let (consumed_cache, fee, new_tx_index) = self.connect_with_derived(
                    &tx_verifier,
                    block,
                    block_index,
                    median_time_past,
                    &mut tx_indices,
                    tx_num,
                )?;

                total_fees = (total_fees + fee).ok_or_else(|| {
                    ConnectTransactionError::FailedToAddAllFeesOfBlock(block.get_id())
                })?;

                flush_to_storage(&mut tx_verifier, consumed_cache)
                    .map_err(ConnectTransactionError::from)?;
                tx_num = new_tx_index;
            } else {
                // connect transactable using current verifier

                tx_verifier.connect_transaction(
                    &TransactionSourceForConnect::Chain {
                        new_block_index: block_index,
                    },
                    &block.transactions()[tx_num],
                    median_time_past,
                    take_front_tx_index(&mut tx_indices),
                )?;
                tx_num += 1;
            }
        }

        tx_verifier
            .check_block_reward(block, Fee(total_fees), block_index.block_height())
            .log_err()?;

        tx_verifier
            .connect_block_reward(
                block_index,
                block.block_reward_transactable(),
                Fee(total_fees),
                block_reward_tx_index,
            )
            .log_err()?;

        Ok(tx_verifier)
    }

    fn connect_with_derived<C, S, U, A, T>(
        &self,
        base_tx_verifier: &TransactionVerifier<C, S, U, A, T>,
        block: &WithId<Block>,
        block_index: &BlockIndex,
        median_time_past: &BlockTimestamp,
        tx_indices: &mut Option<VecDeque<TxMainChainIndex>>,
        mut tx_num: usize,
    ) -> Result<(TransactionVerifierDelta, Amount, usize), ConnectTransactionError>
    where
        C: AsRef<ChainConfig>,
        U: UtxosView,
        A: PoSAccountingView,
        T: TokensAccountingView,
        S: TransactionVerifierStorageRef,
        <S as utxo::UtxosStorageRead>::Error: From<U::Error>,
    {
        let mut tx_verifier = base_tx_verifier.derive_child();
        let mut total_fees = Amount::ZERO;
        while tx_num < block.transactions().len() {
            if self.rng.lock().unwrap().gen::<bool>() {
                // break the loop, which effectively would flush current state to the parent
                break;
            } else {
                // connect transactable using current verifier
                let fee = tx_verifier.connect_transaction(
                    &TransactionSourceForConnect::Chain {
                        new_block_index: block_index,
                    },
                    &block.transactions()[tx_num],
                    median_time_past,
                    take_front_tx_index(tx_indices),
                )?;

                total_fees = (total_fees + fee.0).ok_or_else(|| {
                    ConnectTransactionError::FailedToAddAllFeesOfBlock(block.get_id())
                })?;
                tx_num += 1;
            }
        }
        let cache = tx_verifier.consume()?;
        Ok((cache, total_fees, tx_num))
    }

    fn disconnect_with_base<C, S, M, U, A, T>(
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
        let mut tx_verifier = tx_verifier_maker(storage_backend, chain_config, verifier_config);
        let mut tx_num = i32::try_from(block.transactions().len()).unwrap() - 1;
        while tx_num >= 0 {
            if self.rng.lock().unwrap().gen::<bool>() {
                // derive a new cache
                let (consumed_cache, new_tx_index) =
                    self.disconnect_with_derived(&tx_verifier, block, tx_num)?;

                flush_to_storage(&mut tx_verifier, consumed_cache)
                    .map_err(ConnectTransactionError::from)?;
                tx_num = new_tx_index;
            } else {
                // disconnect transactable using current verifier
                tx_verifier
                    .disconnect_transaction(
                        &TransactionSource::Chain(block.get_id()),
                        &block.transactions()[tx_num as usize],
                    )
                    .log_err()?;
                tx_num -= 1;
            }
        }

        tx_verifier.disconnect_block_reward(block).log_err()?;

        Ok(tx_verifier)
    }

    fn disconnect_with_derived<C, S, U, A, T>(
        &self,
        base_tx_verifier: &TransactionVerifier<C, S, U, A, T>,
        block: &WithId<Block>,
        mut tx_num: i32,
    ) -> Result<(TransactionVerifierDelta, i32), ConnectTransactionError>
    where
        C: AsRef<ChainConfig>,
        U: UtxosView,
        A: PoSAccountingView,
        T: TokensAccountingView,
        S: TransactionVerifierStorageRef,
        <S as utxo::UtxosStorageRead>::Error: From<U::Error>,
    {
        let mut tx_verifier = base_tx_verifier.derive_child();
        while tx_num >= 0 {
            if self.rng.lock().unwrap().gen::<bool>() {
                // break the loop, which effectively would flush current state to the parent
                break;
            } else {
                // disconnect transactable using current verifier
                tx_verifier.disconnect_transaction(
                    &TransactionSource::Chain(block.get_id()),
                    &block.transactions()[tx_num as usize],
                )?;
                tx_num -= 1;
            }
        }
        let cache = tx_verifier.consume()?;
        Ok((cache, tx_num))
    }
}
