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

//! End-to-end test of the scanner daemon's recovery from a WebSocket disconnection:
//! the scanner indexes a few blocks from a real WebSocket RPC server, the connections between
//! the scanner and the server are torn down (the way the node closing its RPC listener or
//! dropping the WebSocket connection would), and after the server becomes reachable again the
//! scanner must reconnect on its own, resume indexing from the tip stored in the database, and
//! converge with the (meanwhile advanced) node tip without being restarted.
//!
//! The scanner side is the real supervision loop of the scanner daemon, including the
//! connection-level error classification, the exponential backoff, and the client re-creation.

// Note: the module must not be called `common`, which would be ambiguous with the `common`
// workspace crate; the path attribute decouples the module name from the file name.
#[path = "common/mod.rs"]
mod test_common;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use api_blockchain_scanner_daemon::run as run_scanner_daemon;
use api_server_backend_test_suite::podman::{Container, Podman};
use api_server_common::storage::{
    impls::postgres::TransactionalApiServerPostgresStorage,
    storage_api::{ApiServerStorageRead, Transactional},
};
use chainstate_test_framework::TestFramework;
use common::{
    chain::GenBlock,
    primitives::{BlockHeight, Id},
};
use jsonrpsee::{
    core::RpcResult,
    types::{ErrorObjectOwned, error::INTERNAL_ERROR_CODE},
};
use randomness::RngExt as _;
use rpc::RpcAuthData;
use serialization::hex_encoded::HexEncoded;
use test_common::proxy::ProxyHandle;
use test_utils::random::{Seed, make_seedable_rng};

#[ctor::ctor]
fn init() {
    logging::init_logging();
}

/// How long to wait for the scanner to catch up with the node tip.
const TIP_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the connections to the "node" stay refused (the outage window, long enough for
/// several backoff steps of the scanner's reconnection attempts).
const OUTAGE_DURATION: Duration = Duration::from_secs(4);

/// The four `chainstate` RPC methods used by the scanner, served by a real WebSocket RPC server
/// backed by the chainstate of a [`TestFramework`]. The method names and the request/response
/// formats match the ones of the real node's RPC, so the scanner cannot tell the difference.
fn make_chainstate_rpc_module(
    framework: Arc<tokio::sync::Mutex<TestFramework>>,
) -> jsonrpsee::RpcModule<Arc<tokio::sync::Mutex<TestFramework>>> {
    let mut module = jsonrpsee::RpcModule::new(framework.clone());

    module
        .register_async_method("chainstate_info", |_params, state, _| async move {
            call_chainstate(Arc::clone(&state), |tf| tf.chainstate.info()).await
        })
        .unwrap();

    module
        .register_async_method("chainstate_best_block_id", |_params, state, _| async move {
            call_chainstate(Arc::clone(&state), |tf| tf.chainstate.get_best_block_id()).await
        })
        .unwrap();

    module
        .register_async_method(
            "chainstate_last_common_ancestor_by_id",
            |params, state, _| async move {
                let (first_block, second_block) = params.parse::<(Id<GenBlock>, Id<GenBlock>)>()?;
                call_chainstate(Arc::clone(&state), move |tf| {
                    tf.chainstate.last_common_ancestor_by_id(&first_block, &second_block)
                })
                .await
            },
        )
        .unwrap();

    module
        .register_async_method(
            "chainstate_get_mainchain_blocks",
            |params, state, _| async move {
                let (from, max_count) = params.parse::<(BlockHeight, usize)>()?;
                call_chainstate(Arc::clone(&state), move |tf| {
                    tf.chainstate.get_mainchain_blocks(from, max_count)
                })
                .await
                .map(|blocks| blocks.into_iter().map(HexEncoded::new).collect::<Vec<_>>())
            },
        )
        .unwrap();

    module
}

async fn call_chainstate<T, F>(
    framework: Arc<tokio::sync::Mutex<TestFramework>>,
    chainstate_call: F,
) -> RpcResult<T>
where
    T: Send + 'static,
    F: FnOnce(&mut TestFramework) -> Result<T, chainstate::ChainstateError> + Send + 'static,
{
    // Note: the chainstate calls are blocking, so they are moved off the async runtime; the
    // `blocking_lock` is allowed here because the blocking pool threads are not the runtime.
    tokio::task::spawn_blocking(move || {
        let mut framework = framework.blocking_lock();
        chainstate_call(&mut framework).map_err(map_chainstate_error)
    })
    .await
    .expect("The chainstate call task has panicked")
}

fn map_chainstate_error(err: chainstate::ChainstateError) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        INTERNAL_ERROR_CODE,
        err.to_string(),
        None::<serde_json::Value>,
    )
}

/// The best block currently known by the scanner, read through an independent storage handle.
///
/// Returns `None` while the storage is not initialized yet: the scanner creates the schema and
/// scans the genesis asynchronously at startup.
async fn scanner_tip(
    storage: &TransactionalApiServerPostgresStorage,
) -> Option<(BlockHeight, Id<GenBlock>)> {
    let db_tx = storage.transaction_ro().await.ok()?;
    let best_block = db_tx.get_best_block().await.ok()?;
    Some((best_block.block_height(), best_block.block_id()))
}

/// Wait until the scanner's tip reaches `expected`; fail after [`TIP_TIMEOUT`].
async fn wait_for_scanner_tip(
    storage: &TransactionalApiServerPostgresStorage,
    expected: Id<GenBlock>,
) {
    let deadline = Instant::now() + TIP_TIMEOUT;
    loop {
        assert!(
            Instant::now() < deadline,
            "Timed out waiting for the scanner to reach the tip {expected}"
        );
        if scanner_tip(storage).await.map(|(_, tip)| tip) == Some(expected) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn scanner_reconnects_after_node_disconnection() {
    // Only run the test if the env var is defined
    if std::env::var("ML_CONTAINERIZED_TESTS").is_err() {
        eprintln!("Warning: Skipping Postgres containerized tests");
        return;
    }

    // Note: one seeded RNG drives the whole test (the framework builder and both phases of
    // block creation), so that a CI failure is locally reproducible with a fixed seed.
    let mut rng = make_seedable_rng(Seed::from_entropy());
    let tf = TestFramework::builder(&mut rng).build();
    let chain_config = tf.chain_config().clone();

    // -----------------------------------------------------------------------------------------
    // The Postgres container and two storage instances (two pools), mirroring the scanner
    // process and the test's independent view of the indexed data.
    // -----------------------------------------------------------------------------------------
    // Note: starting the container involves blocking process invocations (podman/docker CLI),
    // which must not run on the runtime thread (see the note in postgres_stream.rs).
    let (_podman, host_port) = {
        let chain_config = Arc::clone(&chain_config);
        tokio::task::spawn_blocking(move || {
            let mut podman = Podman::new(
                "MintlayerScannerReconnectTest",
                Container::PostgresFromDockerHub,
            )
            .with_env("POSTGRES_HOST_AUTH_METHOD", "trust")
            .with_env(
                "POSTGRES_DB",
                format!("mintlayer-{}", chain_config.chain_type().name()).as_str(),
            )
            .with_port_mapping(None, 5432);
            podman.run();

            let host_port = podman.get_port_mapping(5432).unwrap();
            (podman, host_port)
        })
        .await
        .unwrap()
    };
    let new_storage = || {
        TransactionalApiServerPostgresStorage::new(
            "127.0.0.1",
            host_port,
            "postgres",
            None,
            None,
            5,
            chain_config.clone(),
        )
    };
    let scanner_storage = new_storage().await.unwrap();
    let test_storage = new_storage().await.unwrap();

    // -----------------------------------------------------------------------------------------
    // The "node": a real WebSocket RPC server serving the scanner's chainstate queries, plus a
    // proxy in front of it that lets the test sever the connections.
    // -----------------------------------------------------------------------------------------
    let framework = Arc::new(tokio::sync::Mutex::new(tf));
    let backend_server = jsonrpsee::server::Server::builder().build("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_server.local_addr().unwrap();
    let _backend_server_handle =
        backend_server.start(make_chainstate_rpc_module(Arc::clone(&framework)));

    let (forwarding_tx, _forwarding_rx) = tokio::sync::watch::channel(true);
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = ProxyHandle::start(proxy_listener, backend_addr, forwarding_tx);

    // -----------------------------------------------------------------------------------------
    // The scanner daemon, running exactly as in production (the supervision loop of `run`).
    // -----------------------------------------------------------------------------------------
    let chain_config_for_task = Arc::clone(&chain_config);
    let scanner_address = proxy.addr().to_string();
    let scanner_task = tokio::spawn(async move {
        run_scanner_daemon(
            &chain_config_for_task,
            scanner_address,
            RpcAuthData::None,
            scanner_storage,
        )
        .await
    });

    // Index a few blocks while everything is healthy.
    // Note: the framework mutex is shared between this test (chain building) and the
    // spawn_blocking-backed RPC serving; chain building is itself moved off the runtime thread
    // (it is synchronous, CPU-heavy block processing), and the two serialize for its duration —
    // fine at this scale (the scanner's in-flight calls resume right after).
    // Note: deterministic child seeds are derived from the master RNG, so that a CI failure is
    // locally reproducible with a fixed seed.
    let phase_1_seed = Seed(rng.random_range(0..u64::MAX));
    let phase_2_seed = Seed(rng.random_range(0..u64::MAX));
    let tip_3 = tokio::task::spawn_blocking({
        let framework = Arc::clone(&framework);
        let mut rng = make_seedable_rng(phase_1_seed);
        move || {
            let mut framework = framework.blocking_lock();
            let genesis_id = framework.chain_config().genesis_block_id();
            framework.create_chain_with_empty_blocks(&genesis_id, 3, &mut rng).unwrap()
        }
    })
    .await
    .unwrap();
    proxy.assert_alive();
    wait_for_scanner_tip(&test_storage, tip_3).await;
    assert_eq!(
        scanner_tip(&test_storage).await.map(|(height, _)| height),
        Some(BlockHeight::new(3))
    );

    // -----------------------------------------------------------------------------------------
    // The incident: the connection between the scanner and the node is severed and new
    // connections are refused (like a down node), while the chain keeps advancing.
    // -----------------------------------------------------------------------------------------
    proxy.kill_connections().await;
    proxy.set_forwarding(false);
    tokio::time::sleep(OUTAGE_DURATION).await;

    let tip_5 = tokio::task::spawn_blocking({
        let framework = Arc::clone(&framework);
        let mut rng = make_seedable_rng(phase_2_seed);
        move || {
            let mut framework = framework.blocking_lock();
            framework.create_chain_with_empty_blocks(&tip_3, 2, &mut rng).unwrap()
        }
    })
    .await
    .unwrap();
    assert_ne!(tip_3, tip_5);

    // The scanner must not have given up (or crashed) while the node was unreachable.
    assert!(!scanner_task.is_finished());

    // -----------------------------------------------------------------------------------------
    // The node becomes reachable again; the scanner must reconnect on its own and catch up
    // from its stored tip, without any external restart.
    // -----------------------------------------------------------------------------------------
    proxy.set_forwarding(true);
    proxy.assert_alive();
    wait_for_scanner_tip(&test_storage, tip_5).await;
    assert_eq!(
        scanner_tip(&test_storage).await.map(|(height, _)| height),
        Some(BlockHeight::new(5))
    );

    // The supervision loop is still running (the recovery happened in place).
    assert!(!scanner_task.is_finished());

    // Note: the scanner task is stopped explicitly before the test's handles are dropped:
    // abort cancels it at its next await point and the join below waits for the unwind to
    // finish, so the daemon can never race the closing Postgres pool (no timing heuristics
    // needed).
    scanner_task.abort();
    let _ = scanner_task.await;
}
