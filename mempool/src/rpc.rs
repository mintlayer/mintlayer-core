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

use crate::TxStatus;

#[derive(Clone, Debug, serde::Serialize)]
pub struct GetTxResponse {
    id: Id<Transaction>,
    status: TxStatus,
    transaction: HexEncoded<SignedTransaction>,
}

#[rpc::rpc(server, namespace = "mempool")]
trait MempoolRpc {
    #[method(name = "contains_tx")]
    async fn contains_tx(&self, tx_id: Id<Transaction>) -> rpc::Result<bool>;

    #[method(name = "contains_orphan_tx")]
    async fn contains_orphan_tx(&self, tx_id: Id<Transaction>) -> rpc::Result<bool>;

    #[method(name = "get_transaction")]
    async fn get_transaction(&self, tx_id: Id<Transaction>) -> rpc::Result<Option<GetTxResponse>>;

    #[method(name = "submit_transaction")]
    async fn submit_transaction(&self, tx: HexEncoded<SignedTransaction>) -> rpc::Result<TxStatus>;

    #[method(name = "local_best_block_id")]
    async fn local_best_block_id(&self) -> rpc::Result<Id<GenBlock>>;
}

#[async_trait::async_trait]
impl MempoolRpcServer for super::MempoolHandle {
    async fn contains_tx(&self, tx_id: Id<Transaction>) -> rpc::Result<bool> {
        rpc::handle_result(self.call(move |this| this.contains_transaction(&tx_id)).await)
    }

    async fn contains_orphan_tx(&self, tx_id: Id<Transaction>) -> rpc::Result<bool> {
        rpc::handle_result(self.call(move |this| this.contains_orphan_transaction(&tx_id)).await)
    }

    async fn get_transaction(&self, tx_id: Id<Transaction>) -> rpc::Result<Option<GetTxResponse>> {
        let res: Option<_> = rpc::handle_result(
            self.call(move |this| -> Result<_, crate::error::Error> {
                let res = if let Some(tx) = this.transaction(&tx_id)? {
                    Some((tx, TxStatus::InMempool))
                } else {
                    this.orphan_transaction(&tx_id)?.map(|tx| (tx, TxStatus::InOrphanPool))
                };
                Ok(res)
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
        rpc::handle_result(self.call_mut(|this| this.add_transaction(tx.take())).await.log_err())
    }

    async fn local_best_block_id(&self) -> rpc::Result<Id<GenBlock>> {
        rpc::handle_result(self.call(|this| this.best_block_id()).await)
    }
}
