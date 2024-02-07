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

pub mod handles_client;
pub mod rpc_client;
pub mod wallet_rpc_traits;

// pub async fn make_rpc_client(
//     remote_socket_address: String,
//     rpc_auth: RpcAuthData,
// ) -> Result<rpc_client::NodeRpcClient, NodeRpcError> {
//     rpc_client::NodeRpcClient::new(remote_socket_address, rpc_auth).await
// }

// pub fn make_cold_wallet_rpc_client(chain_config: Arc<ChainConfig>) -> rpc_client::ColdWalletClient {
//     rpc_client::ColdWalletClient::new(chain_config)
// }

// pub async fn make_handles_client(
//     chainstate: ChainstateHandle,
//     mempool: MempoolHandle,
//     block_prod: BlockProductionHandle,
//     p2p: P2pHandle,
// ) -> Result<handles_client::WalletHandlesClient, WalletHandlesClientError> {
//     handles_client::WalletHandlesClient::new(chainstate, mempool, block_prod, p2p).await
// }
