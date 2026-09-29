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

//! End-to-end test of the web server's mempool bridge recovery: the bridge runs against a real
//! WebSocket RPC server (serving the mempool events subscription, plus the method the RPC client
//! checks on connection), behind a proxy that severs the established connections; after the
//! server becomes reachable again, the bridge must re-connect on its own (with its own dedicated
//! client, re-created from scratch) and resume streaming the mempool events.

// Note: the module must not be called `common`, which would be ambiguous with the `common`
// workspace crate; the path attribute decouples the module name from the file name.
#[path = "common/mod.rs"]
mod test_common;

use std::{sync::Arc, time::Duration};

use api_web_server::{
    StreamEventsHandle,
    streaming::{MempoolBridgeConnection, run_mempool_bridge},
};
use common::{
    chain::config::create_unit_test_config,
    primitives::{H256, Id},
};
use jsonrpsee::server::SubscriptionSink;
use mempool::rpc_event::{RpcEvent, RpcTxOrigin};
use rpc::RpcAuthData;
use test_common::proxy::ProxyHandle;

#[ctor::ctor]
fn init() {
    logging::init_logging();
}

/// The time to wait for an expected stream event.
const EVENT_TIMEOUT: Duration = Duration::from_secs(15);

/// How long the connections to the "node" stay severed and new ones refused (long enough for a
/// few backoff steps of the bridge).
const OUTAGE_DURATION: Duration = Duration::from_secs(3);

fn tx_seen_event(n: u64) -> RpcEvent {
    RpcEvent::TransactionProcessed {
        tx_id: Id::new(H256::from_low_u64_be(n)),
        origin: RpcTxOrigin::Local {
            origin: mempool::rpc_event::RpcLocalTxOrigin::Mempool,
        },
        relay: mempool::rpc_event::RpcTxRelayPolicy::DoRelay,
        successful: true,
    }
}

/// A "node" serving exactly the two things the bridge's client needs: the mempool events
/// subscription and the best block id check performed on every (re-)connection. The open
/// subscription sinks are collected into `sinks`, so that the test can push events into the
/// active subscription.
async fn start_mempool_node(
    sinks: Arc<tokio::sync::Mutex<Vec<SubscriptionSink>>>,
) -> SocketAddrWithServer {
    let genesis_id = Arc::new(create_unit_test_config()).genesis_block_id();

    let mut module = jsonrpsee::RpcModule::new(sinks.clone());
    module
        .register_subscription(
            // The method names match the ones the jsonrpsee-generated mempool RPC server and
            // client use, so that the bridge cannot tell this server apart from a real node.
            "mempool_subscribe_to_events",
            "mempool_subscribe_to_events",
            "mempool_unsubscribe_to_events",
            |_params, pending, sinks, _extensions| async move {
                let sink = pending.accept().await.expect("Subscribing failed");
                sinks.lock().await.push(sink);
            },
        )
        .unwrap();
    module
        .register_method(
            "chainstate_best_block_id",
            move |_params, _context, _extensions| Ok::<_, std::convert::Infallible>(genesis_id),
        )
        .unwrap();

    let server = jsonrpsee::server::Server::builder().build("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let _server_handle = server.start(module);
    SocketAddrWithServer {
        addr,
        _server_handle,
    }
}

/// Keeps the RPC server (and thus its subscription sinks) alive.
struct SocketAddrWithServer {
    addr: std::net::SocketAddr,
    _server_handle: jsonrpsee::server::ServerHandle,
}

impl SocketAddrWithServer {
    fn addr(&self) -> std::net::SocketAddr {
        self.addr
    }
}

/// Send a mempool event into the most recently opened subscription.
async fn send_event(sinks: &Arc<tokio::sync::Mutex<Vec<SubscriptionSink>>>, n: u64) {
    let sinks = sinks.lock().await;
    let sink = sinks.last().expect("The bridge must have opened a subscription by now");
    assert!(
        !sink.is_closed(),
        "The latest subscription sink is already closed; the test tried to send an event \
         into a dead subscription (a reconnection raced ahead of the test)"
    );
    // Note: the serialized item is wrapped into the subscription response (with the method name
    // and the subscription id) by the sink itself.
    let item = serde_json::value::to_raw_value(&tx_seen_event(n))
        .expect("Serializing the mempool event failed");
    sink.send(item).await.expect("Sending the event failed");
}

/// Receive the next stream event, failing if it doesn't arrive in time.
async fn recv_event(
    events: &mut tokio::sync::broadcast::Receiver<api_server_common::streaming::StreamEvent>,
) -> api_server_common::streaming::StreamEvent {
    tokio::time::timeout(EVENT_TIMEOUT, events.recv())
        .await
        .expect("timed out waiting for a stream event")
        .expect("the stream event channel has been closed")
}

#[tokio::test]
async fn mempool_bridge_reconnects_after_node_disconnection() {
    // The subscription sinks of the "node", in the order the bridge opened them.
    let sinks = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    // -----------------------------------------------------------------------------------------
    // The "node" (serving the mempool subscription) and the proxy in front of it.
    // -----------------------------------------------------------------------------------------
    let backend = start_mempool_node(Arc::clone(&sinks)).await;
    let (forwarding_tx, _forwarding_rx) = tokio::sync::watch::channel(true);
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = ProxyHandle::start(proxy_listener, backend.addr(), forwarding_tx);

    // -----------------------------------------------------------------------------------------
    // The bridge, with its own dedicated connection parameters, exactly like in production.
    // -----------------------------------------------------------------------------------------
    let handle = StreamEventsHandle::default();
    // Note: the stream subscription is created before the bridge is started, so that it sees
    // every event in order (the broadcast channel only carries events sent after subscribing).
    let mut events = handle.try_subscribe().expect("Subscribing failed");
    let connection = MempoolBridgeConnection::new(
        Arc::new(create_unit_test_config()),
        proxy.addr().to_string(),
        RpcAuthData::None,
    );
    let bridge_task = tokio::spawn(run_mempool_bridge(connection, handle.clone()));

    // Stream a transaction while everything is healthy.
    wait_for_subscription(&proxy, &sinks).await;
    send_event(&sinks, 1).await;
    match recv_event(&mut events.receiver).await {
        api_server_common::streaming::StreamEvent::TxSeen { tx_id, .. } => {
            assert_eq!(tx_id, Id::new(H256::from_low_u64_be(1)));
        }
        unexpected => panic!("Unexpected stream event: {unexpected:?}"),
    }

    // -----------------------------------------------------------------------------------------
    // The incident: the connection between the bridge and the node is severed and new ones are
    // refused, like a node restart or an RPC listener shutdown would.
    // -----------------------------------------------------------------------------------------
    proxy.kill_connections().await;
    proxy.set_forwarding(false);
    tokio::time::sleep(OUTAGE_DURATION).await;

    // The gap must be signaled with a `lag` advisory.
    match recv_event(&mut events.receiver).await {
        api_server_common::streaming::StreamEvent::Lag { .. } => {}
        unexpected => panic!("Unexpected stream event: {unexpected:?}"),
    }

    // The bridge must not have given up (or crashed) while the node was unreachable.
    assert!(!bridge_task.is_finished());

    // -----------------------------------------------------------------------------------------
    // The node becomes reachable again; the bridge must re-connect on its own (re-creating its
    // client, since the old one is broken beyond repair) and resume the stream.
    // -----------------------------------------------------------------------------------------
    proxy.set_forwarding(true);
    wait_for_subscription(&proxy, &sinks).await;

    send_event(&sinks, 2).await;
    match recv_event(&mut events.receiver).await {
        api_server_common::streaming::StreamEvent::TxSeen { tx_id, .. } => {
            assert_eq!(tx_id, Id::new(H256::from_low_u64_be(2)));
        }
        unexpected => panic!("Unexpected stream event: {unexpected:?}"),
    }

    assert!(!bridge_task.is_finished());

    // Note: the bridge is stopped explicitly (instead of being left running until the storage
    // handles are dropped), so that it cannot panic over the closed resources in its loop.
    bridge_task.abort();
    let _ = bridge_task.await;
}

/// Wait until the bridge (re-)opens its subscription; each opening pushes a new sink.
async fn wait_for_subscription(
    proxy: &ProxyHandle,
    sinks: &Arc<tokio::sync::Mutex<Vec<SubscriptionSink>>>,
) {
    let target_count = {
        let sinks = sinks.lock().await;
        sinks.len() + 1
    };
    let deadline = tokio::time::Instant::now() + EVENT_TIMEOUT;
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "Timed out waiting for the bridge to open subscription #{target_count}"
        );
        proxy.assert_alive();
        if sinks.lock().await.len() >= target_count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
