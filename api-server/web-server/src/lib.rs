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

pub mod api;
pub mod config;
pub mod error;
pub mod streaming;
pub mod tx_dependency_ordering;

pub use error::ApiServerWebServerError;
pub use streaming::{StreamEventsHandle, StreamingConfig};

use common::{
    chain::{ChainConfig, SignedTransaction, Transaction},
    primitives::{Id, time::Time},
    time_getter::TimeGetter,
};
use mempool::FeeRate;
use node_comm::{
    node_traits::NodeInterface,
    rpc_client::{NodeRpcClient, NodeRpcError},
};
use std::sync::{Arc, RwLock};

#[async_trait::async_trait]
pub trait TxSubmitClient {
    async fn submit_tx(&self, tx: SignedTransaction) -> Result<(), NodeRpcError>;

    async fn get_feerate_points(&self) -> Result<Vec<(usize, FeeRate)>, NodeRpcError>;
}

/// Queries into the mempool of the connected node.
///
/// The returned transactions are pending: they may be included into a block later,
/// or disappear (e.g. by being evicted or by being included into a block that is
/// later reorganized away).
#[async_trait::async_trait]
pub trait MempoolQueryClient {
    async fn mempool_transaction(
        &self,
        tx_id: Id<Transaction>,
    ) -> Result<Option<SignedTransaction>, NodeRpcError>;

    async fn mempool_transactions(&self) -> Result<Vec<SignedTransaction>, NodeRpcError>;
}

#[async_trait::async_trait]
impl TxSubmitClient for NodeRpcClient {
    async fn submit_tx(&self, tx: SignedTransaction) -> Result<(), NodeRpcError> {
        self.submit_transaction(tx, Default::default()).await
    }

    async fn get_feerate_points(&self) -> Result<Vec<(usize, FeeRate)>, NodeRpcError> {
        self.mempool_get_fee_rate_points().await
    }
}

#[async_trait::async_trait]
impl MempoolQueryClient for NodeRpcClient {
    async fn mempool_transaction(
        &self,
        tx_id: Id<Transaction>,
    ) -> Result<Option<SignedTransaction>, NodeRpcError> {
        NodeInterface::mempool_get_transaction(self, tx_id).await
    }

    async fn mempool_transactions(&self) -> Result<Vec<SignedTransaction>, NodeRpcError> {
        NodeInterface::mempool_get_transactions(self).await
    }
}

pub struct CachedValues {
    pub feerate_points: RwLock<(Time, Vec<(usize, FeeRate)>)>,
}

#[derive(Clone)]
pub struct ApiServerWebServerState<T, R> {
    pub db: T,
    pub chain_config: Arc<ChainConfig>,
    pub rpc: R,
    pub cached_values: Arc<CachedValues>,
    pub time_getter: TimeGetter,
    /// The channel of real-time stream events, fed by the database event pump and the node
    /// mempool bridge, and consumed by the `/api/v2/stream` endpoint.
    pub stream_events: StreamEventsHandle,
}
