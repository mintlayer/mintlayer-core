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

use std::{
    net::{SocketAddr, TcpListener},
    ops::Deref,
};

use clap::Parser;

use api_server_common::{Network, PostgresConfig};
use utils::clap_utils;

const LISTEN_ADDRESS: &str = "127.0.0.1:3000";

#[derive(Debug, Parser)]
#[clap(mut_args(clap_utils::env_adder("API_WEB_SRV")))]
pub struct ApiServerWebServerConfig {
    /// Network
    /// Default: `testnet`
    /// Options: `mainnet`, `testnet`, `regtest`, `signet`
    #[clap(long, value_enum, default_value_t = Network::Mainnet)]
    pub network: Network,

    /// The optional network address and port to listen on
    ///
    /// Format: `<ip>:<port>`
    ///
    /// Default: `127.0.0.1:3000`
    #[clap(long)]
    pub address: Option<ListenAddress>,

    /// Postgres config values
    #[clap(flatten)]
    pub postgres_config: PostgresConfig,

    #[clap(long)]
    pub enable_post_routes: bool,

    /// Optional RPC address
    #[clap(long)]
    pub rpc_address: Option<SocketAddr>,

    /// Path to the RPC cookie file. If not set, the value is read from the default cookie file location.
    #[clap(long)]
    pub rpc_cookie_file: Option<String>,

    /// RPC username (either provide a username and password, or use a cookie file. You cannot use both)
    #[clap(long)]
    pub rpc_username: Option<String>,

    /// RPC password (either provide a username and password, or use a cookie file. You cannot use both)
    #[clap(long)]
    pub rpc_password: Option<String>,
}

#[derive(Clone, Debug, Parser)]
pub struct ListenAddress {
    socket: SocketAddr,
}

impl ListenAddress {
    #[allow(dead_code)]
    pub fn tcp_listener(&self) -> std::net::TcpListener {
        TcpListener::bind(self.socket).expect("Valid listening address")
    }
}

impl Default for ListenAddress {
    fn default() -> Self {
        Self {
            socket: LISTEN_ADDRESS.to_string().parse().expect("Valid listening address"),
        }
    }
}

impl Deref for ListenAddress {
    type Target = SocketAddr;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl From<String> for ListenAddress {
    fn from(address: String) -> Self {
        Self {
            socket: address.parse().expect("Valid listening address"),
        }
    }
}
