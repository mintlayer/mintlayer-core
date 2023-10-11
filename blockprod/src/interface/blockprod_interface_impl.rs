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

use crate::{
    detail::{job_manager::JobKey, BlockProduction},
    BlockProductionError,
};
use common::{
    chain::{Block, SignedTransaction, Transaction},
    primitives::Id,
};
use consensus::GenerateBlockInputData;
use mempool::tx_accumulator::PackingStrategy;

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
        input_data: GenerateBlockInputData,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Block, BlockProductionError> {
        let (block, end_receiver) = self
            .produce_block(input_data, transactions, transaction_ids, packing_strategy)
            .await?;

        // The only error that can happen is if the channel is closed. We don't care about that here.
        let _finished = end_receiver.await;

        Ok(block)
    }
}

impl subsystem::Subsystem for Box<dyn BlockProductionInterface> {
    type Interface = dyn BlockProductionInterface;

    fn interface_ref(&self) -> &Self::Interface {
        self.as_ref()
    }

    fn interface_mut(&mut self) -> &mut Self::Interface {
        self.as_mut()
    }
}
