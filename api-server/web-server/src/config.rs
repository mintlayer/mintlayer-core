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

use std::{net::SocketAddr, ops::Deref};

use clap::Parser;

use api_server_common::{Network, PostgresConfig};
use tokio::net::TcpListener;
use utils::{app_version_with_git_info, clap_utils};
use utils_networking::NetworkAddressWithPort;

// Note: the constants are referenced through their defining crate (instead of
// `crate::streaming`) so that this module does not depend on how the binary's main re-exports
// the module into the crate root.
use api_server_common::streaming;

const LISTEN_ADDRESS: &str = "127.0.0.1:3000";

#[derive(Debug, Parser)]
#[clap(mut_args(clap_utils::env_adder("API_WEB_SRV")))]
#[clap(version(app_version_with_git_info!().to_pretty_string()))]
pub struct ApiServerWebServerConfig {
    /// Network
    /// Default: `testnet`
    /// Options: `mainnet`, `testnet`, `regtest`, `signet`
    #[clap(long, value_enum, default_value_t = Network::Mainnet)]
    pub network: Network,

    /// The optional network address and port to listen on for http API requests
    ///
    /// Format: `<ip>:<port>`
    ///
    /// Default: `127.0.0.1:3000`
    #[clap(long)]
    pub bind_address: Option<ListenAddress>,

    /// Postgres config values
    #[clap(flatten)]
    pub postgres_config: PostgresConfig,

    #[clap(long)]
    pub enable_post_routes: bool,

    /// Optional RPC address
    #[clap(long)]
    pub node_rpc_address: Option<NetworkAddressWithPort>,

    /// Path to the RPC cookie file. If not set, the value is read from the default cookie file location.
    #[clap(long)]
    pub node_rpc_cookie_file: Option<String>,

    /// RPC username (either provide a username and password, or use a cookie file. You cannot use both)
    #[clap(long)]
    pub node_rpc_username: Option<String>,

    /// RPC password (either provide a username and password, or use a cookie file. You cannot use both)
    #[clap(long)]
    pub node_rpc_password: Option<String>,

    /// The maximum number of real-time stream events buffered per connected client; a client that
    /// falls further behind receives a `lag` advisory event instead of the missed events.
    ///
    /// Note: the value must be at least 1.
    #[clap(
        long,
        default_value_t = streaming::DEFAULT_STREAM_EVENTS_BROADCAST_CAPACITY,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..)
    )]
    pub stream_events_broadcast_capacity: usize,

    /// The maximum number of concurrently served real-time stream (SSE) connections.
    ///
    /// Note: the value must be at least 1.
    #[clap(
        long,
        default_value_t = streaming::DEFAULT_STREAM_EVENTS_MAX_SUBSCRIBERS,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..)
    )]
    pub stream_events_max_subscribers: usize,

    /// The interval in seconds between real-time stream event polls; used as a safety net for
    /// missed database notifications.
    ///
    /// Note: the value must be at least 1.
    #[clap(
        long,
        default_value_t = streaming::DEFAULT_STREAM_EVENTS_POLL_INTERVAL.as_secs(),
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub stream_events_poll_interval_secs: u64,

    /// The interval in seconds between keepalive comments sent to connected stream clients.
    ///
    /// Note: the value must be at least 1.
    #[clap(
        long,
        default_value_t = streaming::DEFAULT_STREAM_EVENTS_KEEPALIVE_INTERVAL.as_secs(),
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub stream_events_keepalive_interval_secs: u64,
}

#[derive(Clone, Debug, Parser)]
pub struct ListenAddress {
    socket: SocketAddr,
}

impl ListenAddress {
    #[allow(dead_code)]
    pub async fn tcp_listener(&self) -> TcpListener {
        TcpListener::bind(self.socket).await.expect("Valid listening address")
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
