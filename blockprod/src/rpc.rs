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

//! Block production subsystem RPC handler

use common::{
    chain::Block,
    chain::{SignedTransaction, Transaction},
    primitives::Id,
};
use consensus::GenerateBlockInputData;
use mempool::tx_accumulator::PackingStrategy;
use rpc::Result as RpcResult;
use serialization::hex_encoded::HexEncoded;

use crate::detail::job_manager::JobKey;

#[rpc::rpc(server, client, namespace = "blockprod")]
trait BlockProductionRpc {
    /// When called, the job manager will be notified to send a signal
    /// to all currently running jobs to stop running
    #[method(name = "stop_all")]
    async fn stop_all(&self) -> RpcResult<usize>;

    /// When called, the job manager will be notified to send a signal
    /// to the specified job to stop running
    #[method(name = "stop_job")]
    async fn stop_job(&self, job_id: HexEncoded<JobKey>) -> RpcResult<bool>;

    /// Generate a block with the given transactions
    ///
    /// If `transactions` is `None`, the block will be generated with
    /// available transactions in the mempool
    #[method(name = "generate_block")]
    async fn generate_block(
        &self,
        input_data: HexEncoded<GenerateBlockInputData>,
        transactions: Vec<HexEncoded<SignedTransaction>>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> RpcResult<HexEncoded<Block>>;
}

#[async_trait::async_trait]
impl BlockProductionRpcServer for super::BlockProductionHandle {
    async fn stop_all(&self) -> rpc::Result<usize> {
        rpc::handle_result(
            self.call_async_mut(move |this| Box::pin(async { this.stop_all().await })).await,
        )
    }

    async fn stop_job(&self, job_id: HexEncoded<JobKey>) -> rpc::Result<bool> {
        rpc::handle_result(
            self.call_async_mut(move |this| Box::pin(async { this.stop_job(job_id.take()).await }))
                .await,
        )
    }

    async fn generate_block(
        &self,
        input_data: HexEncoded<GenerateBlockInputData>,
        transactions: Vec<HexEncoded<SignedTransaction>>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> rpc::Result<HexEncoded<Block>> {
        let transactions = transactions.into_iter().map(HexEncoded::take).collect::<Vec<_>>();

        let block: Block = rpc::handle_result(
            self.call_async_mut(move |this| {
                this.generate_block(
                    input_data.take(),
                    transactions,
                    transaction_ids,
                    packing_strategy,
                )
            })
            .await,
        )?;

        Ok(block.into())
    }
}
