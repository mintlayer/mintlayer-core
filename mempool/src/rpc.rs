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

use common::chain::SignedTransaction;
use serialization::Decode;

#[rpc::rpc(server, namespace = "mempool")]
trait MempoolRpc {
    /// Submits a transaction to the mempool.
    #[method(name = "submit_transaction")]
    async fn submit_transaction(&self, tx_hex: String) -> rpc::Result<()>;
}

#[async_trait::async_trait]
impl MempoolRpcServer for super::MempoolHandle {
    async fn submit_transaction(&self, tx_hex: String) -> rpc::Result<()> {
        let tx = hex::decode(tx_hex).map_err(rpc::Error::to_call_error)?;
        let tx = SignedTransaction::decode(&mut &tx[..]).map_err(rpc::Error::to_call_error)?;
        self.call_async_mut(|m| m.add_transaction(tx))
            .await
            .map_err(rpc::Error::to_call_error)?
            .map_err(rpc::Error::to_call_error)
    }
}
