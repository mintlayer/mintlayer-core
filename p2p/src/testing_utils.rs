// Copyright (c) 2022 RBB S.r.l
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

#![allow(clippy::unwrap_used)]

use std::{
    fmt::Debug,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use common::primitives::user_agent::mintlayer_core_user_agent;
use crypto::random::{make_pseudo_rng, Rng};
use p2p_types::socket_address::SocketAddress;
use tokio::time::timeout;

use crate::{
    config::P2pConfig,
    net::{
        default_backend::transport::{
            MpscChannelTransport, NoiseEncryptionAdapter, NoiseTcpTransport, TcpTransportSocket,
        },
        types::{ConnectivityEvent, PeerInfo},
        ConnectivityService, NetworkingService,
    },
    peer_manager::peerdb::storage_impl::PeerDbStorageImpl,
};

/// An interface for creating transports and addresses used in tests.
///
/// This abstraction layer is needed to uniformly create transports and addresses
/// in the tests for different transport implementations.
pub trait TestTransportMaker {
    /// A transport type.
    type Transport;

    /// Creates new transport instance, generating new keys if needed.
    fn make_transport() -> Self::Transport;

    /// Creates a new unused address.
    ///
    /// This should work similar to requesting a port of number 0 when opening a TCP connection.
    fn make_address() -> SocketAddress;
}

pub struct TestTransportTcp {}

impl TestTransportMaker for TestTransportTcp {
    type Transport = TcpTransportSocket;

    fn make_transport() -> Self::Transport {
        TcpTransportSocket::new()
    }

    fn make_address() -> SocketAddress {
        "[::1]:0".parse().unwrap()
    }
}

pub struct TestTransportChannel {}

impl TestTransportMaker for TestTransportChannel {
    type Transport = MpscChannelTransport;

    fn make_transport() -> Self::Transport {
        MpscChannelTransport::new()
    }

    fn make_address() -> SocketAddress {
        "0.0.0.0:0".parse().unwrap()
    }
}

pub struct TestTransportNoise {}

impl TestTransportMaker for TestTransportNoise {
    type Transport = NoiseTcpTransport;

    fn make_transport() -> Self::Transport {
        let stream_adapter = NoiseEncryptionAdapter::gen_new();
        let base_transport = TcpTransportSocket::new();
        NoiseTcpTransport::new(stream_adapter, base_transport)
    }

    fn make_address() -> SocketAddress {
        TestTransportTcp::make_address()
    }
}

pub struct TestAddressMaker {}

impl TestAddressMaker {
    pub fn new_random_address() -> SocketAddress {
        let mut rng = make_pseudo_rng();
        let ip = Ipv6Addr::new(
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
        );
        SocketAddress::new(SocketAddr::new(IpAddr::V6(ip), rng.gen()))
    }
}

pub struct TestChannelAddressMaker {}

/// Can be used in tests only, will panic in case of errors
pub async fn connect_services<T>(
    conn1: &mut T::ConnectivityHandle,
    conn2: &mut T::ConnectivityHandle,
) -> (SocketAddress, PeerInfo, PeerInfo)
where
    T: NetworkingService + Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr = conn2.local_addresses();
    conn1.connect(addr[0]).expect("dial to succeed");

    let (address, peer_info1) = match timeout(Duration::from_secs(5), conn2.poll_next()).await {
        Ok(event) => match event.unwrap() {
            ConnectivityEvent::InboundAccepted {
                address,
                peer_info,
                receiver_address: _,
            } => (address, peer_info),
            event => panic!("expected `InboundAccepted`, got {event:?}"),
        },
        Err(_err) => panic!("did not receive `InboundAccepted` in time"),
    };

    let peer_info2 = match timeout(Duration::from_secs(5), conn1.poll_next()).await {
        Ok(event) => match event.unwrap() {
            ConnectivityEvent::OutboundAccepted {
                address: _,
                peer_info,
                receiver_address: _,
            } => peer_info,
            event => panic!("expected `OutboundAccepted`, got {event:?}"),
        },
        Err(_err) => panic!("did not receive `OutboundAccepted` in time"),
    };

    (address, peer_info1, peer_info2)
}

/// Can be used in tests only, will panic in case of errors
pub async fn connect_and_accept_services<T>(
    conn1: &mut T::ConnectivityHandle,
    conn2: &mut T::ConnectivityHandle,
) -> (SocketAddress, PeerInfo, PeerInfo)
where
    T: NetworkingService + Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let (address, peer_info1, peer_info2) = connect_services::<T>(conn1, conn2).await;

    conn1.accept(peer_info2.peer_id).unwrap();
    conn2.accept(peer_info1.peer_id).unwrap();

    (address, peer_info1, peer_info2)
}

/// Returns first event that is accepted by predicate or panics on timeout.
pub async fn filter_connectivity_event<T, F>(
    conn: &mut T::ConnectivityHandle,
    predicate: F,
) -> crate::Result<ConnectivityEvent>
where
    T: NetworkingService,
    T::ConnectivityHandle: ConnectivityService<T>,
    F: Fn(&crate::Result<ConnectivityEvent>) -> bool,
{
    let recv_fut = async {
        loop {
            let result = conn.poll_next().await;
            if predicate(&result) {
                break result;
            }
        }
    };

    timeout(Duration::from_secs(10), recv_fut)
        .await
        .expect("unexpected timeout receiving connectivity event")
}

/// Returns first event or panics on timeout.
pub async fn get_connectivity_event<T>(
    conn: &mut T::ConnectivityHandle,
) -> crate::Result<ConnectivityEvent>
where
    T: NetworkingService,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    filter_connectivity_event::<T, _>(conn, |_event| true).await
}

pub fn peerdb_inmemory_store() -> PeerDbStorageImpl<storage::inmemory::InMemory> {
    let storage = storage::inmemory::InMemory::new();
    PeerDbStorageImpl::new(storage).unwrap()
}

/// Receive a message from the tokio channel.
/// Panics if the channel is closed or no message received in 10 seconds.
#[macro_export]
macro_rules! expect_recv {
    // Implemented as a macro until #[track_caller] works correctly with async functions
    // (needed to print the caller location if unwraps fail)
    ($x:expr) => {
        tokio::time::timeout(Duration::from_secs(10), $x.recv()).await.unwrap().unwrap()
    };
}

pub fn test_p2p_config() -> P2pConfig {
    P2pConfig {
        bind_addresses: Default::default(),
        socks5_proxy: Default::default(),
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        max_inbound_connections: Default::default(),
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        msg_header_count_limit: Default::default(),
        msg_max_locator_count: Default::default(),
        max_request_blocks_count: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        max_message_size: Default::default(),
        max_peer_tx_announcements: Default::default(),
        max_singular_unconnected_headers: Default::default(),
        sync_stalling_timeout: Default::default(),
    }
}
