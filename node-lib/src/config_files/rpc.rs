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

use std::{net::SocketAddr, str::FromStr};

use crate::RunOptions;
use chainstate_launcher::ChainConfig;
use rpc::RpcConfig;
use serde::{Deserialize, Serialize};

/// The rpc subsystem configuration.
#[must_use]
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct RpcConfigFile {
    /// Address to bind http RPC to
    pub http_bind_address: Option<SocketAddr>,

    /// Whether http RPC is enabled
    pub http_enabled: Option<bool>,

    /// Address to bind websocket RPC to
    pub ws_bind_address: Option<SocketAddr>,

    /// Whether websocket RPC is enabled
    pub ws_enabled: Option<bool>,

    /// Username for RPC HTTP and WebSocket server basic authorization
    pub username: Option<String>,

    /// Password for RPC HTTP and WebSocket server basic authorization
    pub password: Option<String>,

    /// Custom file path for the RPC cookie file
    pub cookie_file: Option<String>,
}

impl From<RpcConfigFile> for RpcConfig {
    fn from(c: RpcConfigFile) -> Self {
        RpcConfig {
            http_bind_address: c.http_bind_address.into(),
            http_enabled: c.http_enabled.into(),
        }
    }
}

impl RpcConfigFile {
    pub fn with_run_options(
        chain_config: &ChainConfig,
        config: RpcConfigFile,
        options: &RunOptions,
    ) -> RpcConfigFile {
        const DEFAULT_HTTP_RPC_ENABLED: bool = true;

        const DEFAULT_WS_RPC_ENABLED: bool = false;
        let default_http_rpc_addr =
            SocketAddr::from_str(&format!("127.0.0.1:{}", chain_config.default_rpc_port()))
                .expect("Can't fail");
        // TODO(PR): get rid of WS RPC
        let default_ws_rpc_addr = SocketAddr::from_str("127.0.0.1:3032").expect("Can't fail");

        let RpcConfigFile {
            http_bind_address,
            http_enabled,
            ws_bind_address,
            ws_enabled,
            username,
            password,
            cookie_file,
        } = config;

        let http_bind_address = options
            .http_rpc_addr
            .unwrap_or_else(|| http_bind_address.unwrap_or(default_http_rpc_addr));
        let http_enabled = options
            .http_rpc_enabled
            .unwrap_or_else(|| http_enabled.unwrap_or(DEFAULT_HTTP_RPC_ENABLED));
        let ws_bind_address = options
            .ws_rpc_addr
            .unwrap_or_else(|| ws_bind_address.unwrap_or(default_ws_rpc_addr));
        let ws_enabled = options
            .ws_rpc_enabled
            .unwrap_or_else(|| ws_enabled.unwrap_or(DEFAULT_WS_RPC_ENABLED));

        let username = username.or(options.rpc_username.clone());
        let password = password.or(options.rpc_password.clone());
        let cookie_file = cookie_file.or(options.rpc_cookie_file.clone());

        RpcConfigFile {
            http_bind_address: Some(http_bind_address),
            http_enabled: Some(http_enabled),
            ws_bind_address: Some(ws_bind_address),
            ws_enabled: Some(ws_enabled),
            username,
            password,
            cookie_file,
        }
    }
}
