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

#[derive(Parser)]
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

// RPC credentials and the database password must never appear in debug output; a debug
// dump of the whole struct is therefore safe by construction.
impl std::fmt::Debug for ApiServerWebServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructure without `..` so a newly added field fails to compile until it is either
        // added here or shown to be safe.
        let Self {
            network,
            bind_address,
            postgres_config,
            enable_post_routes,
            node_rpc_address,
            node_rpc_cookie_file,
            node_rpc_username,
            node_rpc_password,
            stream_events_broadcast_capacity,
            stream_events_max_subscribers,
            stream_events_poll_interval_secs,
            stream_events_keepalive_interval_secs,
        } = self;
        f.debug_struct("ApiServerWebServerConfig")
            .field("network", network)
            .field("bind_address", bind_address)
            .field("node_rpc_address", node_rpc_address)
            .field("node_rpc_cookie_file", node_rpc_cookie_file)
            .field(
                "node_rpc_username",
                &node_rpc_username.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "node_rpc_password",
                &node_rpc_password.as_ref().map(|_| "<redacted>"),
            )
            .field("postgres_config", postgres_config)
            .field("enable_post_routes", enable_post_routes)
            .field(
                "stream_events_broadcast_capacity",
                stream_events_broadcast_capacity,
            )
            .field(
                "stream_events_max_subscribers",
                stream_events_max_subscribers,
            )
            .field(
                "stream_events_poll_interval_secs",
                stream_events_poll_interval_secs,
            )
            .field(
                "stream_events_keepalive_interval_secs",
                stream_events_keepalive_interval_secs,
            )
            .finish()
    }
}

impl ApiServerWebServerConfig {
    /// A loggable summary of the options, omitting every value that can hold a secret.
    /// Keep this method, not a struct dump, in log statements.
    pub fn redacted_summary(&self) -> String {
        // PostgresConfig's Debug output redacts the database password.
        format!(
            "network: {:?}, bind address: {:?}, enable post routes: {}, node RPC address: {:?}, \
             node RPC cookie file: {:?}, postgres: {:?}, stream events broadcast capacity: {}, \
             max subscribers: {}, poll interval: {}s, keepalive interval: {}s",
            self.network,
            self.bind_address,
            self.enable_post_routes,
            self.node_rpc_address,
            self.node_rpc_cookie_file,
            self.postgres_config,
            self.stream_events_broadcast_capacity,
            self.stream_events_max_subscribers,
            self.stream_events_poll_interval_secs,
            self.stream_events_keepalive_interval_secs,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_summary_omits_secrets() {
        // Every value that can also come from the ML_API_WEB_SRV_* environment variables
        // is passed explicitly; values not asserted on may still come from the environment.
        let args = ApiServerWebServerConfig::parse_from([
            "web-server",
            "--network",
            "mainnet",
            "--bind-address",
            "127.0.0.1:3000",
            "--enable-post-routes",
            "--node-rpc-address",
            "127.0.0.1:12345",
            "--node-rpc-username",
            "alice",
            "--node-rpc-password",
            "supersecret",
            "--postgres-host",
            "dbhost",
            "--postgres-user",
            "dbuser",
            "--postgres-password",
            "dbsecret",
        ]);
        let summary = args.redacted_summary();
        assert!(summary.contains("network: Mainnet"));
        assert!(summary.contains("bind address: Some"));
        assert!(summary.contains("127.0.0.1:3000"));
        assert!(summary.contains("enable post routes: true"));
        assert!(summary.contains("node RPC address: Some("));
        assert!(summary.contains("127.0.0.1"));
        assert!(summary.contains("port: 12345"));
        assert!(summary.contains("postgres"));
        assert!(summary.contains("postgres_password: Some(\"<redacted>\")"));
        assert!(!summary.contains("alice"));
        assert!(!summary.contains("supersecret"));
        assert!(!summary.contains("dbsecret"));
        let debug_dump = format!("{args:?}");
        assert!(debug_dump.contains("ApiServerWebServerConfig"));
        assert!(debug_dump.contains("node_rpc_username: Some(\"<redacted>\")"));
        assert!(debug_dump.contains("node_rpc_password: Some(\"<redacted>\")"));
        assert!(debug_dump.contains("postgres_password: Some(\"<redacted>\")"));
        assert!(!debug_dump.contains("alice"));
        assert!(!debug_dump.contains("supersecret"));
        assert!(!debug_dump.contains("dbsecret"));
    }
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
