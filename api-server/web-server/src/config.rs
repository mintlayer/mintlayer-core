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

use api_server_common::{Network, PostgresConfig, RedactedSummary, redact};
use tokio::net::TcpListener;
use utils::{app_version_with_git_info, clap_utils};
use utils_networking::NetworkAddressWithPort;

// Note: the constants are referenced through their defining crate (instead of
// `crate::streaming`) so that this module does not depend on how the binary's main re-exports
// the module into the crate root.
use api_server_common::streaming;

const LISTEN_ADDRESS: &str = "127.0.0.1:3000";

/// Options whose values can hold a secret; their environment-sourced values are hidden
/// from the help output (see the `mut_args` attribute and the guard test below).
// NOTE: when adding a secret-bearing field to this struct, update BOTH the Debug impl
// below (the exhaustive destructure enforces this) AND this list (nothing enforces it;
// the guard test only rejects stale entries, not omissions). A secret-bearing field
// added to the flattened `PostgresConfig` escapes the destructure here: it is guarded
// by `PostgresConfig`'s own Debug impl in api-server-common, but it must still be
// added to this list.
const SECRET_OPTIONS: &[&str] = &["node-rpc-username", "node-rpc-password", "postgres-password"];

#[derive(Parser)]
#[clap(mut_args(clap_utils::env_adder_hiding_env_values("API_WEB_SRV", SECRET_OPTIONS)))]
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
            .field("postgres_config", postgres_config)
            .field("enable_post_routes", enable_post_routes)
            .field("node_rpc_address", node_rpc_address)
            .field("node_rpc_cookie_file", node_rpc_cookie_file)
            .field("node_rpc_username", &redact(node_rpc_username))
            .field("node_rpc_password", &redact(node_rpc_password))
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

// The hand-written Debug impl redacts the secret-bearing fields and guards new fields
// with an exhaustive destructure, so the summary is the Debug output itself.
impl RedactedSummary for ApiServerWebServerConfig {
    fn redacted_summary(&self) -> String {
        format!("{self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use api_server_common::REDACTED;
    use clap::CommandFactory;

    #[test]
    fn secret_options_are_hidden_from_help() {
        let cmd = ApiServerWebServerConfig::command();
        clap_utils::assert_secret_options_hidden(&cmd, SECRET_OPTIONS);

        // Options explicitly classified as non-secret; anything else must be listed in
        // SECRET_OPTIONS or the assertion below fails.
        const NON_SECRET_OPTIONS: &[&str] = &[
            "network",
            "bind-address",
            "enable-post-routes",
            "node-rpc-address",
            "node-rpc-cookie-file",
            "postgres-host",
            "postgres-port",
            "postgres-user",
            "postgres-database",
            "postgres-max-connections",
            "stream-events-broadcast-capacity",
            "stream-events-max-subscribers",
            "stream-events-poll-interval-secs",
            "stream-events-keepalive-interval-secs",
        ];
        let longs: std::collections::HashSet<_> =
            cmd.get_arguments().filter_map(|arg| arg.get_long()).collect();
        let unclassified: Vec<_> = longs
            .iter()
            .copied()
            .filter(|long| !SECRET_OPTIONS.contains(long) && !NON_SECRET_OPTIONS.contains(long))
            .collect();
        assert!(
            unclassified.is_empty(),
            "env-bound options not classified as secret or non-secret: {unclassified:?}"
        );
        let stale: Vec<_> = NON_SECRET_OPTIONS
            .iter()
            .copied()
            .filter(|long| !longs.contains(long))
            .collect();
        assert!(
            stale.is_empty(),
            "non-secret options not found in the command (stale entries): {stale:?}"
        );
    }

    #[test]
    fn redacted_summary_omits_secrets() {
        // Built directly so no ML_API_WEB_SRV_* environment fallback applies.
        let args = ApiServerWebServerConfig {
            network: Network::Mainnet,
            bind_address: Some(ListenAddress {
                socket: "127.0.0.1:3000".parse().unwrap(),
            }),
            postgres_config: PostgresConfig {
                postgres_host: "dbhost".to_string(),
                postgres_port: 5432,
                postgres_user: "dbuser".to_string(),
                postgres_password: Some("dbsecret".to_string()),
                postgres_database: None,
                postgres_max_connections: 10,
            },
            enable_post_routes: true,
            node_rpc_address: Some("127.0.0.1:12345".parse().unwrap()),
            node_rpc_cookie_file: None,
            node_rpc_username: Some("alice".to_string()),
            node_rpc_password: Some("supersecret".to_string()),
            stream_events_broadcast_capacity: streaming::DEFAULT_STREAM_EVENTS_BROADCAST_CAPACITY,
            stream_events_max_subscribers: streaming::DEFAULT_STREAM_EVENTS_MAX_SUBSCRIBERS,
            stream_events_poll_interval_secs: streaming::DEFAULT_STREAM_EVENTS_POLL_INTERVAL
                .as_secs(),
            stream_events_keepalive_interval_secs:
                streaming::DEFAULT_STREAM_EVENTS_KEEPALIVE_INTERVAL.as_secs(),
        };
        let summary = args.redacted_summary();
        // Assertions are value-based rather than pinned to clap's Debug rendering.
        assert!(summary.contains("127.0.0.1:3000"));
        assert!(summary.contains("enable_post_routes"));
        // NetworkAddressWithPort renders the address and port as separate Debug fields,
        // so they are asserted separately.
        assert!(summary.contains("node_rpc_address"));
        assert!(summary.contains("127.0.0.1"));
        assert!(summary.contains("port: 12345"));
        assert!(summary.contains(REDACTED));
        assert!(!summary.contains("alice"));
        assert!(!summary.contains("supersecret"));
        assert!(!summary.contains("dbsecret"));
        let debug_dump = format!("{args:?}");
        assert!(debug_dump.contains("ApiServerWebServerConfig"));
        assert!(debug_dump.contains(REDACTED));
        assert!(!debug_dump.contains("alice"));
        assert!(!debug_dump.contains("supersecret"));
        assert!(!debug_dump.contains("dbsecret"));
    }

    #[test]
    fn redacted_summary_renders_absent_secrets_as_none() {
        // Built directly so no ML_API_WEB_SRV_* environment fallback applies.
        let args = ApiServerWebServerConfig {
            network: Network::Mainnet,
            bind_address: None,
            postgres_config: PostgresConfig {
                postgres_host: "localhost".to_string(),
                postgres_port: 5432,
                postgres_user: "postgres".to_string(),
                postgres_password: None,
                postgres_database: None,
                postgres_max_connections: 10,
            },
            enable_post_routes: false,
            node_rpc_address: None,
            node_rpc_cookie_file: None,
            node_rpc_username: None,
            node_rpc_password: None,
            stream_events_broadcast_capacity: streaming::DEFAULT_STREAM_EVENTS_BROADCAST_CAPACITY,
            stream_events_max_subscribers: streaming::DEFAULT_STREAM_EVENTS_MAX_SUBSCRIBERS,
            stream_events_poll_interval_secs: streaming::DEFAULT_STREAM_EVENTS_POLL_INTERVAL
                .as_secs(),
            stream_events_keepalive_interval_secs:
                streaming::DEFAULT_STREAM_EVENTS_KEEPALIVE_INTERVAL.as_secs(),
        };
        let summary = args.redacted_summary();
        assert!(!summary.contains(REDACTED));
        assert!(summary.contains("node_rpc_username"));
        assert!(summary.contains("node_rpc_password"));
        assert!(summary.contains("postgres_password"));
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
