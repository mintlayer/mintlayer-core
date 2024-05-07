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
    BlockProductionError, TimestampSearchData,
};
use common::{
    chain::{Block, SignedTransaction, Transaction},
    primitives::{BlockHeight, Id},
};
use consensus::{GenerateBlockInputData, PoSTimestampSearchInputData};
use crypto::ephemeral_e2e;
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

    async fn e2e_public_key(&self) -> ephemeral_e2e::EndToEndPublicKey {
        self.e2e_private_key().public_key()
    }

    async fn generate_block_e2e(
        &mut self,
        encrypted_input_data: Vec<u8>,
        e2e_public_key: ephemeral_e2e::EndToEndPublicKey,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Block, BlockProductionError> {
        let shared_secret = self.e2e_private_key().shared_secret(&e2e_public_key);
        let input_data =
            shared_secret.decrypt_then_decode::<GenerateBlockInputData>(&encrypted_input_data)?;
        self.generate_block(input_data, transactions, transaction_ids, packing_strategy)
            .await
    }

    async fn collect_timestamp_search_data_e2e(
        &self,
        encrypted_secret_input_data: Vec<u8>,
        e2e_public_key: ephemeral_e2e::EndToEndPublicKey,
        min_height: BlockHeight,
        max_height: Option<BlockHeight>,
        seconds_to_check_for_height: u64,
        all_timestamps_between_blocks: bool,
    ) -> Result<TimestampSearchData, BlockProductionError> {
        let shared_secret = self.e2e_private_key().shared_secret(&e2e_public_key);
        let input_data = shared_secret
            .decrypt_then_decode::<PoSTimestampSearchInputData>(&encrypted_secret_input_data)?;

        self.collect_timestamp_search_data(
            input_data,
            min_height,
            max_height,
            seconds_to_check_for_height,
            all_timestamps_between_blocks,
        )
        .await
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
