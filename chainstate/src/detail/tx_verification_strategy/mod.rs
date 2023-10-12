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

pub mod default_strategy;
pub use default_strategy::DefaultTransactionVerificationStrategy;

pub mod tx_verification_strategy_utils;

use chainstate_types::BlockIndex;
use common::{
    chain::{block::timestamp::BlockTimestamp, Block, ChainConfig},
    primitives::id::WithId,
};
use pos_accounting::PoSAccountingView;
use tokens_accounting::TokensAccountingView;
use tx_verifier::{
    error::ConnectTransactionError,
    transaction_verifier::{
        config::TransactionVerifierConfig,
        storage::{TransactionVerifierStorageError, TransactionVerifierStorageRef},
        TransactionVerifier,
    },
};
use utxo::UtxosView;

// TODO: replace with trait_alias when stabilized
pub trait TransactionVerifierMakerFn<C, S, U, A, T>:
    Fn(S, C, TransactionVerifierConfig) -> TransactionVerifier<C, S, U, A, T>
{
}

impl<C, S, U, A, T, F> TransactionVerifierMakerFn<C, S, U, A, T> for F where
    F: Fn(S, C, TransactionVerifierConfig) -> TransactionVerifier<C, S, U, A, T>
{
}

/// A trait that specifies how a block will be verified
pub trait TransactionVerificationStrategy: Sized + Send {
    /// Connect the transactions given by block and block_index,
    /// and return a TransactionVerifier with an internal state
    /// that represents them being connected.
    /// Notice that this doesn't modify the internal database/storage
    /// state. It just returns a TransactionVerifier that can be
    /// used to update the database/storage state.
    #[allow(clippy::too_many_arguments)]
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
        S: TransactionVerifierStorageRef<Error = TransactionVerifierStorageError>,
        U: UtxosView,
        C: AsRef<ChainConfig>,
        A: PoSAccountingView,
        T: TokensAccountingView,
        M: TransactionVerifierMakerFn<C, S, U, A, T>,
        <S as utxo::UtxosStorageRead>::Error: From<U::Error>;

    /// Disconnect the transactions given by block and block_index,
    /// and return a TransactionVerifier with an internal state
    /// that represents them being disconnected.
    /// Notice that this doesn't modify the internal database/storage
    /// state. It just returns a TransactionVerifier that can be
    /// used to update the database/storage state.
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
        <S as utxo::UtxosStorageRead>::Error: From<U::Error>;
}
