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

use chainstate::ChainInfo;
use common::{
    chain::{Block, GenBlock},
    primitives::{BlockHeight, Id},
};
use mempool::FeeRate;
use node_comm::{
    node_traits::NodeInterface,
    rpc_client::{NodeRpcClient, NodeRpcError},
};

/// An abstraction for a node that can be called to retrieve information about the blockchain.
#[async_trait::async_trait]
pub trait RemoteNode {
    type Error: std::error::Error;

    async fn chainstate(&self) -> Result<ChainInfo, Self::Error>;
    async fn last_common_ancestor(
        &self,
        first_block: Id<GenBlock>,
        second_block: Id<GenBlock>,
    ) -> Result<Option<(Id<GenBlock>, BlockHeight)>, Self::Error>;
    async fn mainchain_blocks(
        &self,
        from: BlockHeight,
        max_count: usize,
    ) -> Result<Vec<Block>, Self::Error>;

    async fn mempool_feerate_points(&self) -> Result<Vec<(usize, FeeRate)>, Self::Error>;

    /// Returns `true` if the given error indicates a connection-level failure between the
    /// scanner and the node (a broken or unusable connection), as opposed to an
    /// application-level error reported by the node. Connection-level failures are recoverable
    /// by dropping the client and establishing a new connection.
    fn is_connection_error(error: &Self::Error) -> bool
    where
        Self: Sized,
    {
        let _ = error;
        false
    }
}

#[async_trait::async_trait]
impl RemoteNode for NodeRpcClient {
    type Error = NodeRpcError;

    async fn chainstate(&self) -> Result<ChainInfo, Self::Error> {
        self.chainstate_info().await
    }
    async fn last_common_ancestor(
        &self,
        first_block: Id<GenBlock>,
        second_block: Id<GenBlock>,
    ) -> Result<Option<(Id<GenBlock>, BlockHeight)>, Self::Error> {
        self.get_last_common_ancestor(first_block, second_block).await
    }

    async fn mainchain_blocks(
        &self,
        from: BlockHeight,
        max_count: usize,
    ) -> Result<Vec<Block>, Self::Error> {
        self.get_mainchain_blocks(from, max_count).await
    }

    async fn mempool_feerate_points(&self) -> Result<Vec<(usize, FeeRate)>, Self::Error> {
        self.mempool_get_fee_rate_points().await
    }

    fn is_connection_error(error: &NodeRpcError) -> bool {
        NodeRpcError::is_connection_error(error)
    }
}
