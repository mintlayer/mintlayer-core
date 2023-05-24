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

use common::{chain::Block, chain::SignedTransaction};
use consensus::GenerateBlockInputData;
use rpc::Result as RpcResult;
use serialization::hex_encoded::HexEncoded;

use crate::{detail::job_manager::JobKey, BlockProductionError};
use subsystem::subsystem::CallError;

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
        input_data: Option<HexEncoded<GenerateBlockInputData>>,
        transactions: Option<Vec<HexEncoded<SignedTransaction>>>,
    ) -> RpcResult<HexEncoded<Block>>;
}

#[async_trait::async_trait]
impl BlockProductionRpcServer for super::BlockProductionHandle {
    async fn stop_all(&self) -> rpc::Result<usize> {
        let stopped_jobs_count = handle_error(
            self.call_async_mut(move |this| Box::pin(async { this.stop_all().await })).await,
        )?;

        Ok(stopped_jobs_count)
    }

    async fn stop_job(&self, job_id: HexEncoded<JobKey>) -> rpc::Result<bool> {
        let stopped = handle_error(
            self.call_async_mut(move |this| Box::pin(async { this.stop_job(job_id.take()).await }))
                .await,
        )?;

        Ok(stopped)
    }

    async fn generate_block(
        &self,
        input_data: Option<HexEncoded<GenerateBlockInputData>>,
        transactions: Option<Vec<HexEncoded<SignedTransaction>>>,
    ) -> rpc::Result<HexEncoded<Block>> {
        let transactions =
            transactions.map(|txs| txs.into_iter().map(HexEncoded::take).collect::<Vec<_>>());

        let block = handle_error(
            self.call_async_mut(move |this| {
                this.generate_block(input_data.map(HexEncoded::take), transactions)
            })
            .await,
        )?;

        Ok(block.into())
    }
}

fn handle_error<T>(e: Result<Result<T, BlockProductionError>, CallError>) -> rpc::Result<T> {
    e.map_err(rpc::Error::to_call_error)?.map_err(rpc::Error::to_call_error)
}
