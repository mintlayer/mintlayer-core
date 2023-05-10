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
use serialization::hex::HexDecode;

#[rpc::rpc(server, namespace = "mempool")]
trait MempoolRpc {
    #[method(name = "contains_tx")]
    async fn contains_tx(&self, tx_id: Id<Transaction>) -> rpc::Result<bool>;

    #[method(name = "submit_transaction")]
    async fn submit_transaction(&self, tx_hex: String) -> rpc::Result<()>;

    #[method(name = "local_best_block_id")]
    async fn local_best_block_id(&self) -> rpc::Result<Id<GenBlock>>;
}

#[async_trait::async_trait]
impl MempoolRpcServer for super::MempoolHandle {
    async fn contains_tx(&self, tx_id: Id<Transaction>) -> rpc::Result<bool> {
        self.call(move |this| this.contains_transaction(&tx_id))
            .await
            .map_err(rpc::Error::to_call_error)?
            .map_err(rpc::Error::to_call_error)
    }

    async fn submit_transaction(&self, tx_hex: String) -> rpc::Result<()> {
        let tx = SignedTransaction::hex_decode_all(&tx_hex).map_err(rpc::Error::to_call_error)?;
        self.call_mut(|this| this.add_transaction(tx))
            .await
            .map_err(rpc::Error::to_call_error)?
            .map_err(rpc::Error::to_call_error)
    }

    async fn local_best_block_id(&self) -> rpc::Result<Id<GenBlock>> {
        self.call(|this| this.best_block_id()).await.map_err(rpc::Error::to_call_error)
    }
}
