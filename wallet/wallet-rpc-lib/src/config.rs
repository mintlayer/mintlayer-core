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
use crypto::key::hdkd::u31::U31;
use rpc::{rpc_creds::RpcCreds, RpcAuthData};

use crate::types::HardwareWalletType;

#[derive(Clone)]
pub enum NodeRpc {
    ColdWallet,
    HotWallet {
        /// RPC address of the node to connect to
        node_rpc_address: Option<String>,

        /// Node RPC authentication
        node_auth_data: RpcAuthData,
    },
}

/// Configuration options for the wallet service
pub struct WalletServiceConfig {
    /// Chain config to use
    pub chain_config: Arc<ChainConfig>,

    /// Wallet file to operate on
    pub wallet_file: Option<PathBuf>,

    /// Force change the wallet type from hot to cold or from cold to hot
    pub force_change_wallet_type: bool,

    /// Specified if the wallet file is of a hardware wallet type e.g. Trezor
    pub hardware_wallet_type: Option<HardwareWalletType>,

    /// Start staking for account after starting the wallet
    pub start_staking_for_account: Vec<U31>,

    /// Node rpc settings
    pub node_rpc: NodeRpc,
}

impl WalletServiceConfig {
    pub fn new(
        chain_type: ChainType,
        wallet_file: Option<PathBuf>,
        force_change_wallet_type: bool,
        start_staking_for_account: Vec<U31>,
        hardware_wallet_type: Option<HardwareWalletType>,
    ) -> Self {
        Self {
            chain_config: Arc::new(common::chain::config::Builder::new(chain_type).build()),
            wallet_file,
            force_change_wallet_type,
            start_staking_for_account,
            node_rpc: NodeRpc::ColdWallet,
            hardware_wallet_type,
        }
    }

    pub fn with_regtest_options(self, options: ChainConfigOptions) -> anyhow::Result<Self> {
        Ok(self.with_custom_chain_config(Arc::new(regtest_chain_config(&options)?)))
    }

    pub fn with_custom_chain_config(mut self, chain_config: Arc<ChainConfig>) -> Self {
        self.chain_config = chain_config;
        self
    }

    pub fn with_node_rpc_address(mut self, node_rpc_address: String) -> Self {
        self.node_rpc = match self.node_rpc {
            NodeRpc::ColdWallet => NodeRpc::HotWallet {
                node_rpc_address: Some(node_rpc_address),
                node_auth_data: RpcAuthData::None,
            },
            NodeRpc::HotWallet {
                node_rpc_address: _,
                node_auth_data,
            } => NodeRpc::HotWallet {
                node_rpc_address: Some(node_rpc_address),
                node_auth_data,
            },
        };
        self
    }

    pub fn with_username_and_password(self, username: String, password: String) -> Self {
        self.with_node_credentials(RpcAuthData::Basic { username, password })
    }

    pub fn with_node_cookie_file_path(self, cookie_file_path: PathBuf) -> Self {
        self.with_node_credentials(RpcAuthData::Cookie { cookie_file_path })
    }

    pub fn with_node_credentials(mut self, creds: RpcAuthData) -> Self {
        self.node_rpc = match self.node_rpc {
            NodeRpc::ColdWallet => NodeRpc::HotWallet {
                node_rpc_address: None,
                node_auth_data: creds,
            },
            NodeRpc::HotWallet {
                node_rpc_address,
                node_auth_data: _,
            } => NodeRpc::HotWallet {
                node_rpc_address,
                node_auth_data: creds,
            },
        };
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
