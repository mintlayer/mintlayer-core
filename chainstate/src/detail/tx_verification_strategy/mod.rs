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

use chainstate_types::BlockIndex;
use common::{
    chain::{block::timestamp::BlockTimestamp, Block, ChainConfig},
    primitives::id::WithId,
};
use orders_accounting::OrdersAccountingView;
use pos_accounting::PoSAccountingView;
use tokens_accounting::TokensAccountingView;
use tx_verifier::{
    error::ConnectTransactionError,
    transaction_verifier::{
        storage::{TransactionVerifierStorageError, TransactionVerifierStorageRef},
        TransactionVerifier,
    },
};
use utils::shallow_clone::ShallowClone;
use utxo::UtxosView;

// TODO: replace with trait_alias when stabilized
pub trait TransactionVerifierMakerFn<C, S, U, A, T, O>:
    Fn(S, C) -> TransactionVerifier<C, S, U, A, T, O>
{
}

impl<C, S, U, A, T, O, F> TransactionVerifierMakerFn<C, S, U, A, T, O> for F where
    F: Fn(S, C) -> TransactionVerifier<C, S, U, A, T, O>
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
        S: TransactionVerifierStorageRef<Error = TransactionVerifierStorageError>,
        U: UtxosView,
        C: AsRef<ChainConfig> + ShallowClone,
        A: PoSAccountingView,
        T: TokensAccountingView,
        O: OrdersAccountingView,
        M: TransactionVerifierMakerFn<C, S, U, A, T, O>,
        <S as utxo::UtxosStorageRead>::Error: From<U::Error>;

    /// Disconnect the transactions given by block and block_index,
    /// and return a TransactionVerifier with an internal state
    /// that represents them being disconnected.
    /// Notice that this doesn't modify the internal database/storage
    /// state. It just returns a TransactionVerifier that can be
    /// used to update the database/storage state.
    fn disconnect_block<C, S, M, U, A, T, O>(
        &self,
        tx_verifier_maker: M,
        storage_backend: S,
        chain_config: C,
        block_index: &BlockIndex,
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
        <S as utxo::UtxosStorageRead>::Error: From<U::Error>;
}
