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

pub mod ban_score;
pub mod bootstrap;
pub mod query;
pub mod tokens;
pub mod tx_verification_strategy;

mod chainstate_impl;
mod chainstateref;
mod error;
mod info;
mod median_time;
mod orphan_blocks;

pub use chainstate_impl::{BlockSource, Chainstate, OrphanErrorHandler};

pub use chainstate_impl::best_chain_candidates;

pub use self::{
    error::*, info::ChainInfo, median_time::calculate_median_time_past,
    tokens::is_rfc3986_valid_symbol,
};
pub use chainstate_types::Locator;
pub use error::{
    BlockError, CheckBlockError, CheckBlockTransactionsError, DbCommittingContext,
    InitializationError, OrphanCheckError,
};

use tx_verifier::transaction_verifier;
pub use tx_verifier::transaction_verifier::{
    error::{ConnectTransactionError, SpendStakeError, TokensError, TxIndexError},
    storage::TransactionVerifierStorageError,
};

pub use orphan_blocks::OrphanBlocksRef;

#[cfg(test)]
mod test;
