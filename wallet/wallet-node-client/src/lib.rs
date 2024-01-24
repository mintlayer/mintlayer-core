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

use std::sync::Arc;

use blockprod::BlockProductionHandle;
use chainstate::ChainstateHandle;
use common::chain::ChainConfig;
use handles_client::WalletHandlesClientError;
use mempool::MempoolHandle;
use p2p::P2pHandle;
use rpc::RpcAuthData;

use rpc_client::NodeRpcError;

pub mod handles_client;
pub mod node_traits;
pub mod rpc_client;

pub async fn make_rpc_client(
    remote_socket_address: String,
    rpc_auth: RpcAuthData,
) -> Result<rpc_client::NodeRpcClient, NodeRpcError> {
    rpc_client::NodeRpcClient::new(remote_socket_address, rpc_auth).await
}

pub async fn make_opt_rpc_client(
    node_opts: Option<(String, RpcAuthData)>,
    chain_config: Arc<ChainConfig>,
) -> Result<rpc_client::MaybeDummyNode, NodeRpcError> {
    let rpc_client = if let Some((addr, auth)) = node_opts {
        Some(make_rpc_client(addr, auth).await?)
    } else {
        None
    };

    Ok(rpc_client::MaybeDummyNode::new(rpc_client, chain_config))
}

pub async fn make_handles_client(
    chainstate: ChainstateHandle,
    mempool: MempoolHandle,
    block_prod: BlockProductionHandle,
    p2p: P2pHandle,
) -> Result<handles_client::WalletHandlesClient, WalletHandlesClientError> {
    handles_client::WalletHandlesClient::new(chainstate, mempool, block_prod, p2p).await
}
