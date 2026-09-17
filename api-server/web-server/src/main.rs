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

mod api;
mod config;
mod error;

use api_server_common::storage::impls::postgres::{
    PostgresStreamEventSource, TransactionalApiServerPostgresStorage,
};
use api_server_common::streaming::StreamEventsChannel;
use api_web_server::{
    ApiServerWebServerState, CachedValues, StreamEventsHandle, TxSubmitClient, api::web_server,
    config::ApiServerWebServerConfig, streaming,
};
use clap::Parser;
use common::{
    chain::config::{Builder, ChainType},
    primitives::time::Time,
};
use logging::log;
use node_comm::make_rpc_client;
use node_lib::default_rpc_config;
use rpc::RpcAuthData;
use std::sync::{Arc, RwLock};
use utils::{cookie::COOKIE_FILENAME, default_data_dir::default_data_dir_for_chain};

use crate::error::ApiServerWebServerInitError;

utils::enable_rust_backtrace!();

/// Take the process down if one of the background streaming tasks terminates.
fn supervise(name: &'static str, handle: tokio::task::JoinHandle<()>) {
    // Note: the background tasks are meant to run forever; without this supervisor, a panic or
    // any other terminal failure would go completely unnoticed while the REST endpoints keep
    // working, silently disabling the event stream (connected SSE clients would only see
    // keepalives forever). Since a terminated task is unrecoverable by design and the daemon
    // has no graceful-shutdown path (web_server() only returns on error), the process is
    // brought down with a non-zero exit code so that the failure is operationally observable
    // and the service manager restarts the server. This skips destructors and in-flight
    // requests, but that is consistent with how the process terminates anyway (no signal
    // handling is installed).
    tokio::spawn(async move {
        if let Err(err) = handle.await {
            logging::log::error!("CRITICAL: the {name} task terminated: {err}");
            std::process::exit(1);
        }
    });
}

#[tokio::main]
async fn main() -> Result<(), ApiServerWebServerInitError> {
    logging::init_logging();

    let args = ApiServerWebServerConfig::parse();
    log::info!("Command line options: {args:?}");

    let chain_type: ChainType = args.network.into();
    let chain_config = Arc::new(Builder::new(chain_type).build());

    let storage = Arc::new(
        TransactionalApiServerPostgresStorage::new(
            &args.postgres_config.postgres_host,
            args.postgres_config.postgres_port,
            &args.postgres_config.postgres_user,
            args.postgres_config.postgres_password.as_deref(),
            args.postgres_config.postgres_database.as_deref(),
            args.postgres_config.postgres_max_connections,
            chain_config.clone(),
        )
        .await
        .map_err(ApiServerWebServerInitError::PostgresConnectionError)?,
    );

    let stream_events = {
        let channel = StreamEventsChannel::new(args.stream_events_broadcast_capacity);
        let config = streaming::StreamingConfig {
            keepalive_interval: std::time::Duration::from_secs(
                args.stream_events_keepalive_interval_secs,
            ),
            max_subscribers: args.stream_events_max_subscribers,
        };
        StreamEventsHandle::new(channel, config)
    };

    // Note: the event pump needs its own database connection for the LISTEN/NOTIFY wakeups; the
    // periodic poll is the fallback for missed notifications.
    let event_listener = storage
        .new_event_listener()
        .await
        .map_err(ApiServerWebServerInitError::PostgresConnectionError)?;
    let event_source = PostgresStreamEventSource::new(
        Arc::clone(&storage),
        event_listener,
        std::time::Duration::from_secs(args.stream_events_poll_interval_secs),
    );
    supervise(
        "stream event pump",
        tokio::spawn(streaming::run_database_event_pump(
            event_source,
            stream_events.clone(),
        )),
    );

    let rpc_client = {
        let rpc_auth = match (
            args.node_rpc_cookie_file,
            args.node_rpc_username,
            args.node_rpc_password,
        ) {
            (None, None, None) => {
                let cookie_file_path =
                    default_data_dir_for_chain(chain_type.name()).join(COOKIE_FILENAME);
                RpcAuthData::Cookie { cookie_file_path }
            }
            (Some(cookie_file_path), None, None) => RpcAuthData::Cookie {
                cookie_file_path: cookie_file_path.into(),
            },
            (None, Some(username), Some(password)) => RpcAuthData::Basic { username, password },
            _ => {
                return Err(ApiServerWebServerInitError::InvalidConfig(
                    "Invalid RPC cookie/username/password combination".to_owned(),
                ));
            }
        };
        let default_rpc_bind_address =
            || default_rpc_config(&chain_config).bind_address.expect("Can't fail").into();

        let rpc_address = args.node_rpc_address.unwrap_or_else(default_rpc_bind_address);

        make_rpc_client(chain_config.clone(), rpc_address.to_string(), rpc_auth)
            .await
            .map_err(ApiServerWebServerInitError::RpcError)?
    };

    let rpc_client = Arc::new(rpc_client);

    // Note: the mempool events arrive over the node's WebSocket connection and are bridged into
    // the stream event channel; the subscription is re-established after connection loss.
    supervise(
        "mempool bridge",
        tokio::spawn(streaming::run_mempool_bridge(
            Arc::clone(&rpc_client),
            stream_events.clone(),
        )),
    );

    let state = ApiServerWebServerState {
        db: storage,
        chain_config,
        rpc: rpc_client,
        cached_values: Arc::new(CachedValues {
            feerate_points: RwLock::new((Time::from_secs_since_epoch(0), vec![])),
        }),
        time_getter: Default::default(),
        stream_events,
    };

    web_server(
        args.bind_address.unwrap_or_default().tcp_listener().await,
        state,
        args.enable_post_routes,
    )
    .await
    .expect("API Server Web Server failed");

    Ok(())
}
