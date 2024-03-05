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

//! Mempool subsystem RPC handler

use std::num::NonZeroUsize;

use common::{
    chain::{GenBlock, SignedTransaction, Transaction},
    primitives::Id,
};
use mempool_types::{tx_options::TxOptionsOverrides, tx_origin::LocalTxOrigin, TxOptions};
use rpc::description::ValueHint as VH;
use serialization::hex_encoded::HexEncoded;
use utils::tap_log::TapLog;

use crate::{FeeRate, MempoolMaxSize, TxStatus};

use rpc::RpcResult;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GetTxResponse {
    id: Id<Transaction>,
    status: TxStatus,
    transaction: HexEncoded<SignedTransaction>,
}

impl rpc::description::HasValueHint for GetTxResponse {
    const HINT: VH = VH::Object(&[
        ("id", &VH::HEX_STRING),
        ("status", &VH::STRING),
        ("transaction", &VH::HEX_STRING),
    ]);
}

#[rpc::describe]
#[rpc::rpc(server, client, namespace = "mempool")]
trait MempoolRpc {
    /// Returns True if a transaction defined by the given id is found in the mempool.
    #[method(name = "contains_tx")]
    async fn contains_tx(&self, tx_id: Id<Transaction>) -> RpcResult<bool>;

    /// Returns True if a transaction defined by the given id is found in the mempool's orphans.
    ///
    /// An orphan transaction is a transaction with one or more inputs, whose utxos cannot be found.
    #[method(name = "contains_orphan_tx")]
    async fn contains_orphan_tx(&self, tx_id: Id<Transaction>) -> RpcResult<bool>;

    /// Returns the transaction defined by the provided id, given that it is in the pool.
    ///
    /// The returned transaction is returned in an object that contains more information about the transaction.
    /// Returns `None` (null) if the transaction is not found.
    #[method(name = "get_transaction")]
    async fn get_transaction(&self, tx_id: Id<Transaction>) -> RpcResult<Option<GetTxResponse>>;

    /// Get all mempool transactions in a Vec/List, with hex-encoding.
    ///
    /// Notice that this call may be expensive. Use it with caution.
    /// This function is mostly used for testing purposes.
    #[method(name = "transactions")]
    async fn get_all_transactions(&self) -> RpcResult<Vec<HexEncoded<SignedTransaction>>>;

    /// Submit a transaction to the mempool.
    ///
    /// Note that submitting a transaction to the mempool does not guarantee broadcasting it.
    /// Use the p2p rpc interface for that.
    #[method(name = "submit_transaction")]
    async fn submit_transaction(
        &self,
        tx: HexEncoded<SignedTransaction>,
        options: TxOptionsOverrides,
    ) -> RpcResult<()>;

    /// Return the id of the best block, as seen by the mempool.
    ///
    /// Typically this agrees with chainstate, but there could be some delay in responding to chainstate.
    #[method(name = "local_best_block_id")]
    async fn local_best_block_id(&self) -> RpcResult<Id<GenBlock>>;

    /// The total estimated used memory by the mempool.
    #[method(name = "memory_usage")]
    async fn memory_usage(&self) -> RpcResult<usize>;

    /// Get the maximum allowed size of all transactions in the mempool.
    #[method(name = "get_size_limit")]
    async fn get_size_limit(&self) -> RpcResult<usize>;

    /// Set the maximum allowed size of all transactions in the mempool.
    ///
    /// The parameter is either a string, can be written with proper units, such as "100 MB", or "500 KB", or an integer taken as bytes.
    #[method(name = "set_size_limit")]
    async fn set_size_limit(&self, max_size: MempoolMaxSize) -> RpcResult<()>;

    /// Get the current fee rate of the mempool, that puts the transaction in the top X MBs of the mempool.
    /// X, in this description, is provided as a parameter.
    #[method(name = "get_fee_rate")]
    async fn get_fee_rate(&self, in_top_x_mb: usize) -> RpcResult<FeeRate>;

    /// Get the curve data points that represent the fee rate as a function of transaction size.
    #[method(name = "get_fee_rate_points")]
    async fn get_fee_rate_points(&self) -> RpcResult<Vec<(usize, FeeRate)>>;
}

#[async_trait::async_trait]
impl MempoolRpcServer for super::MempoolHandle {
    async fn contains_tx(&self, tx_id: Id<Transaction>) -> rpc::RpcResult<bool> {
        rpc::handle_result(self.call(move |this| this.contains_transaction(&tx_id)).await)
    }

    async fn contains_orphan_tx(&self, tx_id: Id<Transaction>) -> rpc::RpcResult<bool> {
        rpc::handle_result(self.call(move |this| this.contains_orphan_transaction(&tx_id)).await)
    }

    async fn get_all_transactions(&self) -> rpc::RpcResult<Vec<HexEncoded<SignedTransaction>>> {
        rpc::handle_result(
            self.call(move |this| -> Vec<HexEncoded<SignedTransaction>> {
                this.get_all().into_iter().map(HexEncoded::new).collect()
            })
            .await,
        )
    }

    async fn get_transaction(
        &self,
        tx_id: Id<Transaction>,
    ) -> rpc::RpcResult<Option<GetTxResponse>> {
        let res: Option<_> = rpc::handle_result(
            self.call(move |this| {
                this.transaction(&tx_id).map(|tx| (tx, TxStatus::InMempool)).or_else(|| {
                    this.orphan_transaction(&tx_id).map(|tx| (tx, TxStatus::InOrphanPool))
                })
            })
            .await,
        )?;

        Ok(res.map(|(transaction, status)| GetTxResponse {
            id: tx_id,
            status,
            transaction: HexEncoded::new(transaction),
        }))
    }

    async fn submit_transaction(
        &self,
        tx: HexEncoded<SignedTransaction>,
        options: TxOptionsOverrides,
    ) -> rpc::RpcResult<()> {
        let origin = LocalTxOrigin::Mempool;
        let options = TxOptions::default_for(origin.into()).with_overrides(options);
        let res = self
            .call_mut(move |m| m.add_transaction_local(tx.take(), origin, options))
            .await
            .log_err();
        rpc::handle_result(res)
    }

    async fn local_best_block_id(&self) -> rpc::RpcResult<Id<GenBlock>> {
        rpc::handle_result(self.call(|this| this.best_block_id()).await)
    }

    async fn memory_usage(&self) -> rpc::RpcResult<usize> {
        rpc::handle_result(self.call(|this| this.memory_usage()).await)
    }

    async fn get_size_limit(&self) -> rpc::RpcResult<usize> {
        rpc::handle_result(self.call(|this| this.get_size_limit().as_bytes()).await)
    }

    async fn set_size_limit(&self, max_size: MempoolMaxSize) -> rpc::RpcResult<()> {
        rpc::handle_result(self.call_mut(move |this| this.set_size_limit(max_size)).await)
    }

    async fn get_fee_rate(&self, in_top_x_mb: usize) -> rpc::RpcResult<FeeRate> {
        rpc::handle_result(self.call(move |this| this.get_fee_rate(in_top_x_mb)).await)
    }

    async fn get_fee_rate_points(&self) -> RpcResult<Vec<(usize, FeeRate)>> {
        // MIN(1) + 9 = 10, to keep it as const
        const NUM_POINTS: NonZeroUsize = NonZeroUsize::MIN.saturating_add(9);
        rpc::handle_result(self.call(move |this| this.get_fee_rate_points(NUM_POINTS)).await)
    }
}
