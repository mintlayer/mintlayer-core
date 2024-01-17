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
use serde::{Deserialize, Serialize};

use super::DEFAULT_HTTP_RPC_ENABLED;

/// The rpc subsystem configuration.
#[must_use]
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct RpcConfigFile {
    /// Address to bind http RPC to
    pub http_bind_address: Option<SocketAddr>,

    /// Whether http RPC is enabled
    pub http_enabled: Option<bool>,

    /// Username for RPC server basic authorization
    pub username: Option<String>,

    /// Password for RPC server basic authorization
    pub password: Option<String>,

    /// Custom file path for the RPC cookie file
    pub cookie_file: Option<String>,
}

impl RpcConfigFile {
    pub fn default_bind_address(chain_config: &ChainConfig) -> SocketAddr {
        SocketAddr::from_str(&format!(
            "127.0.0.1:{}",
            chain_config.default_node_rpc_port()
        ))
        .expect("Can't fail")
    }

    pub fn with_run_options(
        chain_config: &ChainConfig,
        config_file: RpcConfigFile,
        options: &RunOptions,
    ) -> RpcConfigFile {
        let default_http_rpc_addr = Self::default_bind_address(chain_config);

        let RpcConfigFile {
            http_bind_address,
            http_enabled,
            username,
            password,
            cookie_file,
        } = config_file;

        let http_bind_address = options
            .http_rpc_addr
            .unwrap_or_else(|| http_bind_address.unwrap_or(default_http_rpc_addr));
        let http_enabled = options
            .http_rpc_enabled
            .unwrap_or_else(|| http_enabled.unwrap_or(DEFAULT_HTTP_RPC_ENABLED));

        let username = username.or(options.rpc_username.clone());
        let password = password.or(options.rpc_password.clone());
        let cookie_file = cookie_file.or(options.rpc_cookie_file.clone());

        RpcConfigFile {
            http_bind_address: Some(http_bind_address),
            http_enabled: Some(http_enabled),
            username,
            password,
            cookie_file,
        }
    }
}
