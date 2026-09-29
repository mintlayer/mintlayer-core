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

//! A minimal TCP proxy in front of a (WebSocket) RPC server, used by the tests to sever the
//! connections between a daemon and the server behind it exactly like a node restart or an RPC
//! listener shutdown would, without having to re-bind the daemon-facing port (which would be
//! unreliable, because the closed connections would leave the port in TIME_WAIT).
//!
//! Note: the proxy task has no shutdown path; like the daemons under test, it runs until the
//! test process ends (its failure is observable through [`ProxyHandle::assert_alive`]).

use std::net::SocketAddr;
use std::sync::Arc;

/// The handle of a running [`run_proxy`].
pub struct ProxyHandle {
    addr: SocketAddr,
    forwarding: tokio::sync::watch::Sender<bool>,
    connections: Arc<tokio::sync::Mutex<Vec<[tokio::task::JoinHandle<()>; 2]>>>,
    task: tokio::task::JoinHandle<()>,
    /// The number of accepted connections dropped because forwarding was disabled or the
    /// backend was unreachable; exposed for diagnostics in test failures.
    refused: Arc<std::sync::atomic::AtomicUsize>,
}

impl ProxyHandle {
    /// Starts the proxy: it accepts connections on `listener` and pipes them to `backend_addr`
    /// while forwarding is enabled; while it is disabled, the accepted connections are dropped
    /// immediately (the "node is down" behavior).
    pub fn start(
        listener: tokio::net::TcpListener,
        backend_addr: SocketAddr,
        forwarding: tokio::sync::watch::Sender<bool>,
    ) -> Self {
        let addr = listener.local_addr().unwrap();
        let forwarding_rx = forwarding.subscribe();
        let connections = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let refused = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let task = tokio::spawn(run_proxy(
            listener,
            backend_addr,
            forwarding_rx,
            Arc::clone(&connections),
            Arc::clone(&refused),
        ));

        Self {
            addr,
            forwarding,
            connections,
            task,
            refused,
        }
    }

    /// The address the proxied daemons connect to.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Switch the proxy between forwarding (`true`) and refusing new connections (`false`).
    pub fn set_forwarding(&self, forwarding: bool) {
        self.forwarding.send(forwarding).expect("The proxy has crashed");
    }

    /// Tear down all established proxied connections; the daemons behind them see their
    /// WebSocket connections being closed.
    pub async fn kill_connections(&self) {
        let mut connections = self.connections.lock().await;
        for connection in connections.drain(..) {
            for task in connection {
                task.abort();
            }
        }
    }

    /// Panic unless the proxy task is still running; to be called from the test polling loops,
    /// so that a dead proxy surfaces as a test failure at the right place instead of as a
    /// mysterious timeout on a subsequent connection wait.
    pub fn assert_alive(&self) {
        assert!(!self.task.is_finished(), "The proxy task has terminated");
    }

    /// The number of connections the proxy has dropped without forwarding them (forwarding
    /// disabled, or the backend unreachable); useful for diagnosing test failures.
    pub fn refused_connections(&self) -> usize {
        self.refused.load(std::sync::atomic::Ordering::Relaxed)
    }
}

async fn run_proxy(
    listener: tokio::net::TcpListener,
    backend_addr: SocketAddr,
    mut forwarding: tokio::sync::watch::Receiver<bool>,
    connections: Arc<tokio::sync::Mutex<Vec<[tokio::task::JoinHandle<()>; 2]>>>,
    refused: Arc<std::sync::atomic::AtomicUsize>,
) {
    use std::sync::atomic::Ordering;

    loop {
        let (client_socket, _) = tokio::select! {
            accepted = listener.accept() => accepted.expect("The proxy listener has failed"),
            _ = forwarding.changed() => {
                // Note: the established connections are not affected by the switch; killing them
                // is a separate, explicit step.
                continue;
            }
        };

        if !*forwarding.borrow() {
            // The "node is down": drop the accepted connection right away.
            refused.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        let Ok(backend_socket) = tokio::net::TcpStream::connect(backend_addr).await else {
            // The backend is unreachable; behave like a closed connection.
            refused.fetch_add(1, Ordering::Relaxed);
            continue;
        };

        let (mut client_read, mut client_write) = client_socket.into_split();
        let (mut backend_read, mut backend_write) = backend_socket.into_split();
        let client_to_backend = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut client_read, &mut backend_write).await;
        });
        let backend_to_client = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut backend_read, &mut client_write).await;
        });

        let mut connections = connections.lock().await;
        // Reap the forwarding tasks of dead connections: once either direction has finished,
        // the other is dead by construction (its peer socket has been dropped with the task).
        connections.retain(|pair| !pair[0].is_finished() || !pair[1].is_finished());
        connections.push([client_to_backend, backend_to_client]);
    }
}
