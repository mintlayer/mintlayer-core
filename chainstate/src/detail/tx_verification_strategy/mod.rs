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
pub mod disposable_strategy;

#[cfg(any(test, feature = "randomized"))]
pub mod randomized_strategy;
#[cfg(any(test, feature = "randomized"))]
pub use randomized_strategy::RandomizedTransactionVerificationStrategy;

pub use {
    default_strategy::DefaultTransactionVerificationStrategy,
    disposable_strategy::DisposableTransactionVerificationStrategy,
};

use crate::BlockError;
use chainstate_types::{BlockIndex, BlockIndexHandle};
use common::{
    chain::{Block, ChainConfig},
    primitives::id::WithId,
};
use tx_verifier::transaction_verifier::{
    storage::TransactionVerifierStorageRef, TransactionVerifier,
};

/// A trait that specifies how a block will be verified
pub trait TransactionVerificationStrategy: Sized + Send {
    /// Connect the transactions given by block and block_index,
    /// and return a TransactionVerifier with an internal state
    /// that represents them being connected.
    /// Notice that this doesn't modify the internal database/storage
    /// state. It just returns a TransactionVerifier that can be
    /// used to update the database/storage state.
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
        M: Fn(&'a S, &'a ChainConfig) -> TransactionVerifier<'a, S>;

    /// Disconnect the transactions given by block and block_index,
    /// and return a TransactionVerifier with an internal state
    /// that represents them being disconnected.
    /// Notice that this doesn't modify the internal database/storage
    /// state. It just returns a TransactionVerifier that can be
    /// used to update the database/storage state.
    fn disconnect_block<'a, S, M>(
        &self,
        tx_verifier_maker: M,
        storage_backend: &'a S,
        chain_config: &'a ChainConfig,
        block: &WithId<Block>,
    ) -> Result<TransactionVerifier<'a, S>, BlockError>
    where
        S: TransactionVerifierStorageRef,
        M: Fn(&'a S, &'a ChainConfig) -> TransactionVerifier<'a, S>;
}
