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

use common::{
    chain::{GenBlock, SignedTransaction, Transaction},
    primitives::Id,
};
use serialization::hex_encoded::HexEncoded;
use utils::tap_error_log::LogError;

use crate::{MempoolMaxSize, TxOrigin, TxStatus};

use rpc::Result as RpcResult;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GetTxResponse {
    id: Id<Transaction>,
    status: TxStatus,
    transaction: HexEncoded<SignedTransaction>,
}

#[rpc::rpc(server, client, namespace = "mempool")]
trait MempoolRpc {
    #[method(name = "contains_tx")]
    async fn contains_tx(&self, tx_id: Id<Transaction>) -> RpcResult<bool>;

    #[method(name = "contains_orphan_tx")]
    async fn contains_orphan_tx(&self, tx_id: Id<Transaction>) -> RpcResult<bool>;

    #[method(name = "get_transaction")]
    async fn get_transaction(&self, tx_id: Id<Transaction>) -> RpcResult<Option<GetTxResponse>>;

    /// Get all mempool transaction IDs
    #[method(name = "transactions")]
    async fn get_all_transactions(&self) -> RpcResult<Vec<HexEncoded<SignedTransaction>>>;

    #[method(name = "submit_transaction")]
    async fn submit_transaction(&self, tx: HexEncoded<SignedTransaction>) -> RpcResult<TxStatus>;

    #[method(name = "local_best_block_id")]
    async fn local_best_block_id(&self) -> RpcResult<Id<GenBlock>>;

    #[method(name = "memory_usage")]
    async fn memory_usage(&self) -> RpcResult<usize>;

    #[method(name = "get_max_size")]
    async fn get_max_size(&self) -> RpcResult<usize>;

    // TODO: We should accept more convenient ways of setting the size in addition to plain byte
    // count, e.g. "200MB" instead of 200000000
    #[method(name = "set_max_size")]
    async fn set_max_size(&self, max_size: usize) -> RpcResult<()>;

    #[method(name = "get_fee_rate")]
    async fn get_fee_rate(&self) -> RpcResult<u128>;
}

#[async_trait::async_trait]
impl MempoolRpcServer for super::MempoolHandle {
    async fn contains_tx(&self, tx_id: Id<Transaction>) -> rpc::Result<bool> {
        rpc::handle_result(self.call(move |this| this.contains_transaction(&tx_id)).await)
    }

    async fn contains_orphan_tx(&self, tx_id: Id<Transaction>) -> rpc::Result<bool> {
        rpc::handle_result(self.call(move |this| this.contains_orphan_transaction(&tx_id)).await)
    }

    async fn get_all_transactions(&self) -> rpc::Result<Vec<HexEncoded<SignedTransaction>>> {
        rpc::handle_result(
            self.call(move |this| -> Vec<HexEncoded<SignedTransaction>> {
                this.get_all().into_iter().map(HexEncoded::new).collect()
            })
            .await,
        )
    }

    async fn get_transaction(&self, tx_id: Id<Transaction>) -> rpc::Result<Option<GetTxResponse>> {
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

    async fn submit_transaction(&self, tx: HexEncoded<SignedTransaction>) -> rpc::Result<TxStatus> {
        let res = self
            .call_mut(move |this| this.add_transaction(tx.take(), TxOrigin::LocalMempool))
            .await
            .log_err();
        rpc::handle_result(res)
    }

    async fn local_best_block_id(&self) -> rpc::Result<Id<GenBlock>> {
        rpc::handle_result(self.call(|this| this.best_block_id()).await)
    }

    async fn memory_usage(&self) -> rpc::Result<usize> {
        rpc::handle_result(self.call(|this| this.memory_usage()).await)
    }

    async fn get_max_size(&self) -> rpc::Result<usize> {
        rpc::handle_result(self.call(|this| this.get_max_size().as_bytes()).await)
    }

    async fn set_max_size(&self, max_size: usize) -> rpc::Result<()> {
        let max_size = MempoolMaxSize::from_bytes(max_size);
        rpc::handle_result(self.call_mut(move |this| this.set_max_size(max_size)).await)
    }

    async fn get_fee_rate(&self) -> rpc::Result<u128> {
        rpc::handle_result(self.call(move |this| this.get_fee_rate()).await)
    }
}
