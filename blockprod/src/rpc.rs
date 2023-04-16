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
    chain::{Destination, SignedTransaction},
};

use serialization::{hex::HexDecode, hex::HexEncode};

use crate::{detail::JobKey, BlockProductionError};
use subsystem::subsystem::CallError;

#[rpc::rpc(server, namespace = "blockprod")]
trait BlockProductionRpc {
    /// Stop block production
    #[method(name = "stop_all")]
    async fn stop_all(&self) -> rpc::Result<()>;

    // Stop a specific job
    #[method(name = "stop_job")]
    async fn stop_job(&self, job_id: String) -> rpc::Result<()>;

    /// Generate a block with the supplied transactions to the specified reward destination
    /// If transactions are None, the block will be generated with available transactions in the mempool
    #[method(name = "generate_block")]
    async fn generate_block(
        &self,
        reward_destination_hex: String,
        transactions_hex: Option<Vec<String>>,
    ) -> rpc::Result<String>;
}

#[async_trait::async_trait]
impl BlockProductionRpcServer for super::BlockProductionHandle {
    async fn stop_all(&self) -> rpc::Result<()> {
        handle_error(self.call_mut(|this| this.stop_all()).await)
    }

    async fn stop_job(&self, job_id_hex: String) -> rpc::Result<()> {
        let job_id = JobKey::hex_decode_all(job_id_hex).map_err(rpc::Error::to_call_error)?;

        handle_error(self.call_mut(move |this| this.stop_job(job_id)).await)
    }

    async fn generate_block(
        &self,
        reward_destination_hex: String,
        transactions_hex: Option<Vec<String>>,
    ) -> rpc::Result<String> {
        let reward_destination = Destination::hex_decode_all(reward_destination_hex)
            .map_err(rpc::Error::to_call_error)?;

        let signed_transactions = match transactions_hex {
            Some(txs) => Some(
                txs.into_iter()
                    .map(SignedTransaction::hex_decode_all)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(rpc::Error::to_call_error)?,
            ),
            None => None,
        };

        let block = handle_error(
            self.call_async_mut(move |this| {
                this.generate_block(reward_destination, signed_transactions)
            })
            .await,
        )?;

        Ok(Block::hex_encode(&block))
    }
}

fn handle_error<T>(e: Result<Result<T, BlockProductionError>, CallError>) -> rpc::Result<T> {
    e.map_err(rpc::Error::to_call_error)?.map_err(rpc::Error::to_call_error)
}
