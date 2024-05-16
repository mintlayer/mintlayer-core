// Copyright (c) 2023 RBB S.r.l
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

use crate::{detail::job_manager::JobKey, BlockProductionError, TimestampSearchData};
use common::{
    chain::{Block, PoolId, SignedTransaction, Transaction},
    primitives::{BlockHeight, Id},
};
use consensus::GenerateBlockInputData;
use crypto::ephemeral_e2e;
use mempool::tx_accumulator::PackingStrategy;

#[async_trait::async_trait]
pub trait BlockProductionInterface: Send + Sync {
    /// When called, the job manager will be notified to send a signal
    /// to all currently running jobs to stop running
    async fn stop_all(&mut self) -> Result<usize, BlockProductionError>;

    /// When called, the job manager will be notified to send a signal
    /// to the specified job to stop running
    async fn stop_job(&mut self, job_id: JobKey) -> Result<bool, BlockProductionError>;

    /// Generate a block with the given transactions
    ///
    /// There are 3 levels of priority for transactions to be included
    /// in the generated block - `transactions` contains the highest
    /// priority transactions, followed by `transaction_ids` which
    /// refer to transactions within the mempool.
    ///
    /// If `include_mempool` is true, the rest of the block will be
    /// filled with available transactions from the mempool.
    async fn generate_block(
        &mut self,
        input_data: GenerateBlockInputData,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Block, BlockProductionError>;

    async fn e2e_public_key(&self) -> ephemeral_e2e::EndToEndPublicKey;

    /// Same as generate_block, but with end-to-end encryption for the secret data
    async fn generate_block_e2e(
        &mut self,
        encrypted_input_data: Vec<u8>,
        e2e_public_key: ephemeral_e2e::EndToEndPublicKey,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Block, BlockProductionError>;

    /// Collect the search data needed by the `timestamp_searcher` module.
    ///
    /// See `timestamp_searcher::collect_timestamp_search_data` for the details about
    /// the parameters.
    async fn collect_timestamp_search_data(
        &self,
        pool_id: PoolId,
        min_height: BlockHeight,
        max_height: Option<BlockHeight>,
        seconds_to_check_for_height: u64,
        check_all_timestamps_between_blocks: bool,
    ) -> Result<TimestampSearchData, BlockProductionError>;
}
