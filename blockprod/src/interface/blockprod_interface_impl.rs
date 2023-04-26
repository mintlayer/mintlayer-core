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

use common::chain::{Block, Destination, SignedTransaction};

use crate::{
    detail::{job_manager::JobKey, BlockProduction},
    BlockProductionError,
};

use super::blockprod_interface::BlockProductionInterface;

#[async_trait::async_trait]
impl BlockProductionInterface for BlockProduction {
    async fn stop_all(&mut self) -> Result<usize, BlockProductionError> {
        self.stop_all_jobs().await
    }

    async fn stop_job(&mut self, job_id: JobKey) -> Result<bool, BlockProductionError> {
        self.stop_job(job_id).await
    }

    async fn generate_block(
        &mut self,
        reward_destination: Destination,
        transactions: Option<Vec<SignedTransaction>>,
    ) -> Result<Block, BlockProductionError> {
        let transactions = match transactions {
            Some(txs) => crate::detail::TransactionsSource::Provided(txs),
            None => crate::detail::TransactionsSource::Mempool,
        };

        let (block, end_receiver) = self.produce_block(reward_destination, transactions).await?;

        // The only error that can happen is if the channel is closed. We don't care about that here.
        let _finished = end_receiver.await;

        Ok(block)
    }
}
