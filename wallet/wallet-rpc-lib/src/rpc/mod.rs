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

mod interface;
mod server_impl;
pub mod types;

use std::sync::Arc;

use common::chain::ChainConfig;
pub use interface::{WalletRpcClient, WalletRpcServer};
pub use rpc::{rpc_creds::RpcCreds, Rpc, RpcAuthData};

use crate::{service::NodeRpcClient, WalletHandle, WalletRpcConfig};

struct WalletRpc {
    wallet: WalletHandle,
    node: NodeRpcClient,
    chain_config: Arc<ChainConfig>,
}

impl WalletRpc {
    fn new(wallet: WalletHandle, node: NodeRpcClient, chain_config: Arc<ChainConfig>) -> Self {
        Self {
            wallet,
            node,
            chain_config,
        }
    }
}

pub async fn start(
    wallet_handle: WalletHandle,
    node_rpc: NodeRpcClient,
    config: WalletRpcConfig,
    chain_config: Arc<ChainConfig>,
) -> anyhow::Result<rpc::Rpc> {
    let WalletRpcConfig {
        bind_addr,
        auth_credentials,
    } = config;

    rpc::Builder::new(bind_addr, auth_credentials)
        .register(WalletRpc::new(wallet_handle, node_rpc, chain_config).into_rpc())
        .build()
        .await
}
