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
    chain::{Block, SignedTransaction, Transaction},
    primitives::{BlockHeight, Id},
};
use consensus::GenerateBlockInputData;
use crypto::ephemeral_e2e::{self, EndToEndPublicKey};
use mempool::tx_accumulator::PackingStrategy;
use rpc::RpcResult;
use serialization::hex_encoded::HexEncoded;

use crate::{detail::job_manager::JobKey, TimestampSearchData};

#[rpc::describe]
#[rpc::rpc(server, client, namespace = "blockprod")]
trait BlockProductionRpc {
    /// When called, the job manager will be notified to send a signal
    /// to all currently running jobs to stop running to stop block production.
    #[method(name = "stop_all")]
    async fn stop_all(&self) -> RpcResult<usize>;

    /// When called, the job manager will be notified to send a signal
    /// to the specified job to stop running.
    #[method(name = "stop_job")]
    async fn stop_job(&self, job_id: HexEncoded<JobKey>) -> RpcResult<bool>;

    /// Generate a block with the given transactions.
    ///
    /// Parameters:
    /// - `input_data`: The input data for block generation, such as staking key.
    /// - `transactions`: The transactions prioritized to be included in the block.
    ///                   Notice that it's the responsibility of the caller to ensure that the transactions are valid.
    ///                   If the transactions are not valid, the block will be rejected and will not be included in the blockchain.
    ///                   It's preferable to use `transaction_ids` instead, where the mempool will ensure that the transactions are valid
    ///                   against the current state of the blockchain.
    /// - `transaction_ids`: The transaction IDs of the transactions to be included in the block from the mempool.
    /// - `packing_strategy`: Whether or not to include transactions from the mempool in the block, other than the ones specified in `transaction_ids`.
    #[method(name = "generate_block")]
    async fn generate_block(
        &self,
        input_data: HexEncoded<GenerateBlockInputData>,
        transactions: Vec<HexEncoded<SignedTransaction>>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> RpcResult<HexEncoded<Block>>;

    /// Get the public key to be used for end-to-end encryption.
    #[method(name = "e2e_public_key")]
    async fn e2e_public_key(&self) -> RpcResult<HexEncoded<ephemeral_e2e::EndToEndPublicKey>>;

    /// Same as `generate_block`, but with end-to-end encryption.
    ///
    /// The end-to-end encryption helps in protecting the signing key, so that it is much harder
    /// for an eavesdropper to get it with pure http/websocket connection.
    /// The e2e_public_key is the pubic key for end-to-end encryption of the client.
    #[method(name = "generate_block_e2e")]
    async fn generate_block_e2e(
        &self,
        encrypted_input_data: Vec<u8>,
        e2e_public_key: HexEncoded<EndToEndPublicKey>,
        transactions: Vec<HexEncoded<SignedTransaction>>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> RpcResult<HexEncoded<Block>>;

    /// Collect the search data needed by the `timestamp_searcher` module.
    ///
    /// See `timestamp_searcher::collect_timestamp_search_data` for the details about
    /// the parameters.
    #[method(name = "collect_timestamp_search_data_e2e")]
    async fn collect_timestamp_search_data_e2e(
        &self,
        encrypted_secret_input_data: Vec<u8>,
        e2e_public_key: HexEncoded<EndToEndPublicKey>,
        min_height: BlockHeight,
        max_height: Option<BlockHeight>,
        seconds_to_check_for_height: u64,
        all_timestamps_between_blocks: bool,
    ) -> RpcResult<HexEncoded<TimestampSearchData>>;
}

#[async_trait::async_trait]
impl BlockProductionRpcServer for super::BlockProductionHandle {
    async fn stop_all(&self) -> rpc::RpcResult<usize> {
        rpc::handle_result(
            self.call_async_mut(move |this| Box::pin(async { this.stop_all().await })).await,
        )
    }

    async fn stop_job(&self, job_id: HexEncoded<JobKey>) -> rpc::RpcResult<bool> {
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
    ) -> rpc::RpcResult<HexEncoded<Block>> {
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

    async fn e2e_public_key(&self) -> rpc::RpcResult<HexEncoded<EndToEndPublicKey>> {
        let public_key: EndToEndPublicKey =
            rpc::handle_result(self.call_async(move |this| this.e2e_public_key()).await)?;

        Ok(public_key.into())
    }

    async fn generate_block_e2e(
        &self,
        encrypted_input_data: Vec<u8>,
        e2e_public_key: HexEncoded<EndToEndPublicKey>,
        transactions: Vec<HexEncoded<SignedTransaction>>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> RpcResult<HexEncoded<Block>> {
        let transactions = transactions.into_iter().map(HexEncoded::take).collect::<Vec<_>>();
        let e2e_public_key = e2e_public_key.take();

        let block: Block = rpc::handle_result(
            self.call_async_mut(move |this| {
                this.generate_block_e2e(
                    encrypted_input_data,
                    e2e_public_key,
                    transactions,
                    transaction_ids,
                    packing_strategy,
                )
            })
            .await,
        )?;

        Ok(block.into())
    }

    async fn collect_timestamp_search_data_e2e(
        &self,
        encrypted_secret_input_data: Vec<u8>,
        e2e_public_key: HexEncoded<EndToEndPublicKey>,
        min_height: BlockHeight,
        max_height: Option<BlockHeight>,
        seconds_to_check_for_height: u64,
        all_timestamps_between_blocks: bool,
    ) -> RpcResult<HexEncoded<TimestampSearchData>> {
        let e2e_public_key = e2e_public_key.take();

        let search_data: TimestampSearchData = rpc::handle_result(
            self.call_async_mut(move |this| {
                this.collect_timestamp_search_data_e2e(
                    encrypted_secret_input_data,
                    e2e_public_key,
                    min_height,
                    max_height,
                    seconds_to_check_for_height,
                    all_timestamps_between_blocks,
                )
            })
            .await,
        )?;

        Ok(search_data.into())
    }
}
