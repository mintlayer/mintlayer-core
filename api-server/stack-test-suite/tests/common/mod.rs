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

//! Helpers shared between the test binaries of this crate.
//!
//! Note: this module is linked separately into each test binary, so an item used by only some of
//! the binaries must not be reported as unused; hence the blanket `allow` below.

#![allow(dead_code)]

use api_server_common::storage::impls::in_memory::transactional::TransactionalApiServerInMemoryStorage;
use api_web_server::{
    ApiServerWebServerState, CachedValues, MempoolQueryClient, TxSubmitClient, api::web_server,
};
use common::{
    chain::{SignedTransaction, Transaction, config::create_unit_test_config},
    primitives::{Id, Idable, time::get_time},
};
use hex::ToHex;
use mempool::FeeRate;
use node_comm::rpc_client::NodeRpcError;
use serialization::hex_encoded::HexEncoded;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// A no-op RPC client for the web server state under test.
pub struct DummyRPC {}

#[async_trait::async_trait]
impl TxSubmitClient for DummyRPC {
    async fn submit_tx(&self, _: SignedTransaction) -> Result<(), NodeRpcError> {
        Ok(())
    }

    async fn get_feerate_points(&self) -> Result<Vec<(usize, FeeRate)>, NodeRpcError> {
        Ok(vec![])
    }
}

#[async_trait::async_trait]
impl MempoolQueryClient for DummyRPC {
    async fn mempool_transaction(
        &self,
        _: Id<Transaction>,
    ) -> Result<Option<SignedTransaction>, NodeRpcError> {
        Ok(None)
    }

    async fn mempool_transactions(&self) -> Result<Vec<SignedTransaction>, NodeRpcError> {
        Ok(vec![])
    }
}

/// An RPC client mock with an in-memory mempool.
///
/// Transactions submitted through [`TxSubmitClient::submit_tx`] are added to the mock
/// mempool in the order of submission, imitating the insertion order of the mempool
/// of a node. The mock does not validate the transactions (e.g. it does not check
/// that the spent outputs exist), just like a node mempool accepts chain of unconfirmed
/// transactions.
pub struct MempoolRPC {
    mempool: RwLock<Vec<SignedTransaction>>,
}

impl MempoolRPC {
    pub fn new() -> Self {
        Self {
            mempool: RwLock::new(vec![]),
        }
    }
}

impl Default for MempoolRPC {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl TxSubmitClient for MempoolRPC {
    async fn submit_tx(&self, tx: SignedTransaction) -> Result<(), NodeRpcError> {
        self.mempool.write().unwrap().push(tx);
        Ok(())
    }

    async fn get_feerate_points(&self) -> Result<Vec<(usize, FeeRate)>, NodeRpcError> {
        Ok(vec![])
    }
}

#[async_trait::async_trait]
impl MempoolQueryClient for MempoolRPC {
    async fn mempool_transaction(
        &self,
        tx_id: Id<Transaction>,
    ) -> Result<Option<SignedTransaction>, NodeRpcError> {
        Ok(self
            .mempool
            .read()
            .unwrap()
            .iter()
            .find(|tx| tx.transaction().get_id() == tx_id)
            .cloned())
    }

    async fn mempool_transactions(&self) -> Result<Vec<SignedTransaction>, NodeRpcError> {
        Ok(self.mempool.read().unwrap().clone())
    }
}

/// The barrier request ensuring that the spawned web server is up: given that the
/// listener port is open, the request to the `url` blocks until a response is made
/// (by the web server, which takes the listener over), and the response is returned
/// to the caller. The request is bounded by a timeout, so that a hung server task
/// does not hang the test.
///
/// On any failure, the `task` running the web server is aborted and awaited, and the
/// test panics with the failure context, including the outcome of the task (with the
/// actual panic message, if the task panicked).
pub async fn wait_for_web_server(
    task: &mut tokio::task::JoinHandle<()>,
    addr: std::net::SocketAddr,
    url: &str,
) -> reqwest::Response {
    /// The time to wait for the web server to respond to the barrier request.
    const BARRIER_TIMEOUT: Duration = Duration::from_secs(30);

    let request = reqwest::get(format!("http://{}:{}{url}", addr.ip(), addr.port()));

    let err = match tokio::time::timeout(BARRIER_TIMEOUT, request).await {
        Ok(Ok(response)) => return response,
        Ok(Err(err)) => format!("request failed: {err}"),
        Err(_timed_out) => format!("the request timed out after {BARRIER_TIMEOUT:?}"),
    };

    task.abort();
    let join_result = task.await;
    let outcome = match join_result {
        Ok(()) => "the task finished".to_string(),
        Err(join_err) if join_err.is_cancelled() => "the task was aborted".to_string(),
        Err(join_err) => {
            let payload = join_err.into_panic();
            let message = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".to_string());
            format!("the task panicked: {message}")
        }
    };
    panic!("the web server died before responding on {addr}: {err}; {outcome}");
}

/// Spawn the web server backed by the [`MempoolRPC`] client and an empty in-memory
/// api-server storage.
///
/// Imitating the `spawn_webserver` helper of the test binaries, the returned response
/// is the response to the `url` request, which doubles as the barrier ensuring that
/// the server is up before the test proceeds.
pub async fn spawn_webserver_with_mempool(
    url: &str,
) -> (
    tokio::task::JoinHandle<()>,
    reqwest::Response,
    Arc<MempoolRPC>,
    std::net::SocketAddr,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let rpc = Arc::new(MempoolRPC::new());

    let mut task = tokio::spawn({
        let rpc = std::sync::Arc::clone(&rpc);
        async move {
            let web_server_state = {
                let chain_config = Arc::new(create_unit_test_config());
                let storage = TransactionalApiServerInMemoryStorage::new(&chain_config);

                ApiServerWebServerState {
                    db: Arc::new(storage),
                    chain_config: Arc::clone(&chain_config),
                    rpc,
                    cached_values: Arc::new(CachedValues {
                        feerate_points: RwLock::new((get_time(), vec![])),
                    }),
                    time_getter: Default::default(),
                    stream_events: Default::default(),
                }
            };

            web_server(listener, web_server_state, true).await.unwrap();
        }
    });

    let response = wait_for_web_server(&mut task, addr, url).await;

    (task, response, rpc, addr)
}

/// Abort the task and observe its outcome: tolerated if cancelled or completed, panics
/// with the actual panic message otherwise.
///
/// Generic over the task output.
pub async fn shutdown_task<T: Send + 'static>(handle: tokio::task::JoinHandle<T>) {
    handle.abort();
    match handle.await {
        Ok(_) => {}
        Err(err) if err.is_cancelled() => {}
        Err(err) => {
            let payload = err.into_panic();
            let message = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".to_string());
            panic!("task panicked: {message}");
        }
    }
}

/// Submit the transaction through the POST endpoint, imitating a user of the
/// api-server, and return the hex-encoded id of the submitted transaction.
pub async fn submit_transaction(addr: std::net::SocketAddr, tx: SignedTransaction) -> String {
    let tx_id = tx.transaction().get_id().to_hash().encode_hex::<String>();

    let hex_tx: HexEncoded<SignedTransaction> = tx.into();
    let response = reqwest::Client::new()
        .post(format!(
            "http://{}:{}/api/v2/transaction",
            addr.ip(),
            addr.port()
        ))
        .body(hex_tx.to_string())
        .send()
        .await
        .unwrap();

    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(status, 200, "transaction submission failed: {body}");

    tx_id
}

/// The value of the `event:` field of an SSE frame, if any.
pub fn frame_event_name(frame: &str) -> Option<&str> {
    frame.lines().find_map(|line| line.strip_prefix("event: "))
}

/// The value of the `data:` field of an SSE frame, if any.
pub fn frame_data(frame: &str) -> Option<&str> {
    frame.lines().find_map(|line| line.strip_prefix("data: "))
}
