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

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use common::chain::config::{
    regtest_options::{regtest_chain_config, ChainConfigOptions},
    ChainConfig, ChainType,
};
use rpc::{rpc_creds::RpcCreds, RpcAuthData};

/// Configuration options for the wallet service
pub struct WalletServiceConfig {
    /// Chain config to use
    pub chain_config: Arc<ChainConfig>,

    /// Wallet file to operate on
    pub wallet_file: Option<PathBuf>,

    /// RPC address of the node to connect to
    pub wallet_rpc_address: Option<String>,

    /// Node RPC authentication
    pub wallet_rpc_credentials: RpcAuthData,
}

impl WalletServiceConfig {
    pub fn new(
        chain_type: ChainType,
        wallet_file: Option<PathBuf>,
        chain_config_options: ChainConfigOptions,
    ) -> anyhow::Result<Self> {
        let chain_config = match chain_type {
            ChainType::Regtest => Arc::new(regtest_chain_config(&chain_config_options)?),
            _ => Arc::new(common::chain::config::Builder::new(chain_type).build()),
        };
        Ok(Self {
            chain_config,
            wallet_file,
            wallet_rpc_address: None,
            wallet_rpc_credentials: RpcAuthData::None,
        })
    }

    pub fn with_custom_chain_config(mut self, chain_config: Arc<ChainConfig>) -> Self {
        self.chain_config = chain_config;
        self
    }

    pub fn with_node_rpc_address(mut self, node_rpc_address: String) -> Self {
        self.wallet_rpc_address = Some(node_rpc_address);
        self
    }

    pub fn with_username_and_password(self, username: String, password: String) -> Self {
        self.with_node_credentials(RpcAuthData::Basic { username, password })
    }

    pub fn with_node_cookie_file_path(self, cookie_file_path: PathBuf) -> Self {
        self.with_node_credentials(RpcAuthData::Cookie { cookie_file_path })
    }

    pub fn with_node_credentials(mut self, creds: RpcAuthData) -> Self {
        self.wallet_rpc_credentials = creds;
        self
    }

    pub fn apply_option<T>(self, f: impl FnOnce(Self, T) -> Self, opt: Option<T>) -> Self {
        match opt {
            None => self,
            Some(opt) => f(self, opt),
        }
    }
}

/// Configuration options for the wallet RPC interface
pub struct WalletRpcConfig {
    /// Address to listen on
    pub bind_addr: SocketAddr,

    /// Authentication credentials needed to use the interface
    pub auth_credentials: Option<RpcCreds>,
}

impl WalletRpcConfig {
    pub fn default_port(chain_type: ChainType) -> u16 {
        match chain_type {
            ChainType::Mainnet => 3034,
            ChainType::Testnet => 13034,
            ChainType::Regtest => 23034,
            ChainType::Signet => 33034,
        }
    }
}
