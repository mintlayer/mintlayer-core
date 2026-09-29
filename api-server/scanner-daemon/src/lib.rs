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

//! The blockchain scanner daemon: keeps the API server storage in sync with the node.
//!
//! The daemon is designed to run next to a node whose WebSocket RPC connection can come and go:
//! connection-level failures (the node being down, the connection being closed or stalled) are
//! recovered in place by re-establishing the connection with an exponential backoff, always
//! resuming the indexing from the tip stored in the database. Only genuinely non-recoverable
//! problems (an invalid configuration, a storage version mismatch, etc.) terminate the daemon.

pub mod backoff;

use std::sync::Arc;
use std::time::Duration;

use api_blockchain_scanner_lib::blockchain_state::BlockchainState;
use api_blockchain_scanner_lib::sync::local_state::LocalBlockchainState;
use api_server_common::storage::{
    impls::{CURRENT_STORAGE_VERSION, postgres::TransactionalApiServerPostgresStorage},
    storage_api::{
        ApiServerStorage, ApiServerStorageError, ApiServerStorageRead, ApiServerStorageWrite,
        ApiServerTransactionRw,
    },
};
use backoff::ReconnectBackoff;
use common::chain::ChainConfig;
use node_comm::{
    make_rpc_client,
    rpc_client::{NodeRpcClient, NodeRpcError},
};
use randomness::Rng;
use rpc::RpcAuthData;

/// The initial delay between connection attempts, doubled on every failed attempt.
const RECONNECT_DELAY_INITIAL: Duration = Duration::from_secs(1);
/// The upper bound of the delay between connection attempts.
const RECONNECT_DELAY_MAX: Duration = Duration::from_secs(60);
/// The initial delay before re-attempting a sync that failed with a non-connection error; the
/// delay grows with the same exponential schedule as the reconnection attempts.
const SYNC_ERROR_DELAY: Duration = Duration::from_secs(1);
/// How long to wait for a connection attempt to complete before treating it as failed. The
/// bridge/scanner must never depend on the library's default timeouts for its no-wedge
/// guarantees.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// The state of an ongoing outage of the connection to the node.
struct Outage {
    /// When the connection was first found to be broken.
    started: std::time::Instant,
    /// The number of reconnection attempts made so far, including the failed ones.
    attempts: u64,
}

impl Outage {
    fn new() -> Self {
        Self {
            started: std::time::Instant::now(),
            attempts: 0,
        }
    }
}

pub async fn make_postgres_storage(
    postgres_host: String,
    postgres_port: u16,
    postgres_user: String,
    postgres_password: Option<String>,
    postgres_database: Option<String>,
    postgres_max_connections: u32,
    chain_config: Arc<ChainConfig>,
) -> Result<TransactionalApiServerPostgresStorage, ApiServerScannerError> {
    TransactionalApiServerPostgresStorage::new(
        &postgres_host,
        postgres_port,
        &postgres_user,
        postgres_password.as_deref(),
        postgres_database.as_deref(),
        postgres_max_connections,
        chain_config,
    )
    .await
    .map_err(ApiServerScannerError::PostgresConnectionError)
}

pub async fn run<S: ApiServerStorage>(
    chain_config: &Arc<ChainConfig>,
    node_rpc_address: String,
    node_rpc_auth: RpcAuthData,
    mut storage: S,
) -> Result<(), ApiServerScannerError> {
    // Note: the storage initialization failures below panic instead of returning `Err`, on
    // purpose: the issue-mandated behavior is that a storage that cannot be initialized (a
    // schema/transaction problem or a version mismatch) must fail fast and loud, rather than
    // keep retrying against a database in an unknown state. A Postgres that is unreachable at
    // startup already fails gracefully with an error in `make_postgres_storage`.
    let mut local_block = {
        let needs_reinit =
            {
                let db_tx = storage.transaction_rw().await.unwrap_or_else(|e| {
                    panic!("Initial transaction for initialization failed {}", e)
                });
                if !db_tx
                    .is_initialized()
                    .await
                    .unwrap_or_else(|e| panic!("Storage initialization checking failed {}", e))
                {
                    true
                } else {
                    let storage_version = db_tx
                        .get_storage_version()
                        .await
                        .unwrap_or_else(|e| panic!("Storage version read failed {}", e))
                        .expect("cannot be empty");
                    if storage_version != CURRENT_STORAGE_VERSION {
                        true
                    } else {
                        db_tx.commit().await.unwrap_or_else(|e| {
                            panic!("Storage initialization commit failed {}", e)
                        });
                        false
                    }
                }
            };

        if needs_reinit {
            reinitialize_and_rescan(chain_config, storage).await
        } else {
            BlockchainState::new(Arc::clone(chain_config), storage)
        }
    };

    supervise_sync(
        chain_config,
        node_rpc_address,
        node_rpc_auth,
        &mut local_block,
        &mut ReconnectBackoff::new(RECONNECT_DELAY_INITIAL, RECONNECT_DELAY_MAX),
        &mut ReconnectBackoff::new(SYNC_ERROR_DELAY, RECONNECT_DELAY_MAX),
        &mut randomness::make_true_rng(),
    )
    .await
}

/// Re-initialize the storage (wiping the indexed data) and scan the genesis block, so that the
/// scanning starts over from scratch; used both for a fresh database and for a storage version
/// upgrade.
async fn reinitialize_and_rescan<S: ApiServerStorage>(
    chain_config: &Arc<ChainConfig>,
    mut storage: S,
) -> BlockchainState<S> {
    let mut db_tx = storage.transaction_rw().await.unwrap_or_else(|e| {
        panic!(
            "Initialization transaction for re-initialization failed {}",
            e
        )
    });
    db_tx
        .reinitialize_storage(chain_config)
        .await
        .unwrap_or_else(|e| panic!("Storage (re-)initialization failed {}", e));
    db_tx
        .commit()
        .await
        .unwrap_or_else(|e| panic!("Storage initialization commit failed {}", e));

    let mut local_block = BlockchainState::new(Arc::clone(chain_config), storage);
    local_block
        .scan_genesis(chain_config.genesis_block().as_ref())
        .await
        .expect("Can't scan genesis");
    local_block
}

/// The supervision loop of the scanner: keeps the local state in sync with the node, recovering
/// in place from connection-level failures by re-creating the RPC client with an exponential
/// backoff and resuming the indexing from the tip stored in the local state.
///
/// Note: the backoff is only reset after a successful sync (not merely after a successful
/// connect), so that a node that accepts connections but immediately drops them or fails to
/// serve cannot pin the retry rate at the initial delay.
///
/// Note: non-connection errors (e.g. the node being behind the local tip right after it has
/// been restarted) are not fixed by reconnecting, so the client is kept and only the sync is
/// retried, with the delay growing via `sync_error_backoff` so that a persistent failure (e.g.
/// a broken database) cannot flood the logs.
async fn supervise_sync<S: ApiServerStorage>(
    chain_config: &Arc<ChainConfig>,
    node_rpc_address: String,
    node_rpc_auth: RpcAuthData,
    local_block: &mut BlockchainState<S>,
    backoff: &mut ReconnectBackoff,
    sync_error_backoff: &mut ReconnectBackoff,
    rng: &mut impl Rng,
) -> Result<(), ApiServerScannerError> {
    // Note: the client is created lazily (and re-created after every connection-level failure),
    // so that a node that is down at startup does not abort the daemon; `None` means that the
    // connection to the node is currently broken and must be re-established.
    let mut rpc_client: Option<NodeRpcClient> = None;
    // Note: `outage` is `Some` if and only if `rpc_client` is `None`.
    let mut outage: Option<Outage> = None;

    loop {
        if rpc_client.is_none() {
            rpc_client = Some(loop {
                // Note: the connection attempt is bounded by a timeout so that a stalled
                // handshake (the node accepting the TCP connection but never completing the
                // WebSocket handshake) cannot wedge a round forever without any log output;
                // expiry is treated like any other connection failure.
                let connection = tokio::time::timeout(
                    CONNECT_TIMEOUT,
                    make_rpc_client(
                        Arc::clone(chain_config),
                        node_rpc_address.clone(),
                        node_rpc_auth.clone(),
                    ),
                )
                .await;
                match connection {
                    Ok(Ok(client)) => break client,
                    Ok(Err(err)) if NodeRpcError::is_connection_error(&err) => {
                        let outage = outage.get_or_insert_with(Outage::new);
                        outage.attempts += 1;
                        let delay = backoff.next_delay(rng);
                        logging::log::warn!(
                            "Failed to connect to the node (attempt {}, elapsed {:?}): {err}; \
                            retrying in {delay:?}",
                            outage.attempts,
                            outage.started.elapsed(),
                        );
                        tokio::time::sleep(delay).await;
                    }
                    // A connection cannot be established, but the reason is not a temporary
                    // connectivity problem (e.g. an invalid address); retrying is pointless.
                    Ok(Err(err)) => return Err(ApiServerScannerError::RpcError(err)),
                    Err(_timed_out) => {
                        let outage = outage.get_or_insert_with(Outage::new);
                        outage.attempts += 1;
                        let delay = backoff.next_delay(rng);
                        logging::log::warn!(
                            "Timed out connecting to the node (attempt {}, elapsed {:?}); \
                            retrying in {delay:?}",
                            outage.attempts,
                            outage.started.elapsed(),
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            });

            if let Some(outage) = outage.take() {
                let local_height = local_block
                    .best_block()
                    .await
                    .map_or(common::primitives::BlockHeight::zero(), |(height, _)| {
                        height
                    });
                logging::log::info!(
                    "Scanner reconnected to the node after {} attempt(s) ({:?} elapsed); \
                    resuming from height {}",
                    outage.attempts,
                    outage.started.elapsed(),
                    local_height,
                );
            }
        }

        let client = rpc_client.as_ref().expect("The RPC client must have been established above");

        match api_blockchain_scanner_lib::sync::sync_once(chain_config, client, local_block).await {
            Ok(()) => {
                // Note: the backoff is only reset here (after a successful sync), not after a
                // successful connect: a flapping node must not pin the retry rate at the
                // initial delay.
                backoff.reset();
                sync_error_backoff.reset();
            }
            Err(err) if err.is_connection_error() => {
                // The client is permanently broken (e.g. the node has closed the WebSocket
                // connection); drop it and re-connect on the next iteration.
                rpc_client = None;
                let outage = outage.get_or_insert_with(Outage::new);
                outage.attempts += 1;
                let delay = backoff.next_delay(rng);
                logging::log::warn!(
                    "Lost the connection to the node (attempt {}, elapsed {:?}): {err}; \
                    re-connecting in {delay:?}",
                    outage.attempts,
                    outage.started.elapsed(),
                );
                tokio::time::sleep(delay).await;
            }
            Err(err) => {
                // Note: the client is kept (re-connecting cannot fix the failure); the delay
                // grows for as long as the errors persist so that the loop cannot flood the
                // logs, and resets after a successful sync.
                let delay = sync_error_backoff.next_delay(rng);
                logging::log::error!("Scanner sync error: {err}; retrying in {delay:?}");
                tokio::time::sleep(delay).await;
            }
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ApiServerScannerError {
    #[error("RPC error: {0}")]
    RpcError(node_comm::rpc_client::NodeRpcError),
    #[error("Invalid config: {0}")]
    InvalidConfig(String),
    #[error("Postgres connection error: {0}")]
    PostgresConnectionError(ApiServerStorageError),
}
