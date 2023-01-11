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
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use crypto::random::{make_pseudo_rng, Rng};
use tokio::time::timeout;

use crate::net::{
    mock::transport::{
        MockChannelTransport, NoiseEncryptionAdapter, NoiseTcpTransport, TcpTransportSocket,
    },
    types::{ConnectivityEvent, PeerInfo},
    ConnectivityService, NetworkingService,
};

/// An interface for creating transports and addresses used in tests.
///
/// This abstraction layer is needed to uniformly create transports and addresses
/// in the tests for different mocks transport implementations.
pub trait TestTransportMaker {
    /// A transport type.
    type Transport;

    /// An address type.
    type Address: Clone + Eq + std::fmt::Debug + std::hash::Hash + Send + Sync + ToString;

    /// Creates new transport instance, generating new keys if needed.
    fn make_transport() -> Self::Transport;

    /// Creates a new unused address.
    ///
    /// This should work similar to requesting a port of number 0 when opening a TCP connection.
    fn make_address() -> Self::Address;
}

pub struct TestTransportTcp {}

impl TestTransportMaker for TestTransportTcp {
    type Transport = TcpTransportSocket;

    type Address = SocketAddr;

    fn make_transport() -> Self::Transport {
        TcpTransportSocket::new()
    }

    fn make_address() -> Self::Address {
        "[::1]:0".parse().unwrap()
    }
}

pub struct TestTransportChannel {}

impl TestTransportMaker for TestTransportChannel {
    type Transport = MockChannelTransport;

    type Address = u32;

    fn make_transport() -> Self::Transport {
        MockChannelTransport::new()
    }

    fn make_address() -> Self::Address {
        0
    }
}

pub struct TestTransportNoise {}

impl TestTransportMaker for TestTransportNoise {
    type Transport = NoiseTcpTransport;

    type Address = SocketAddr;

    fn make_transport() -> Self::Transport {
        let stream_adapter = NoiseEncryptionAdapter::gen_new();
        let base_transport = TcpTransportSocket::new();
        NoiseTcpTransport::new(stream_adapter, base_transport)
    }

    fn make_address() -> Self::Address {
        TestTransportTcp::make_address()
    }
}

/// An interface for creating random addresses.
pub trait RandomAddressMaker {
    /// An address type.
    type Address;

    /// Creates a new random address
    fn new() -> Self::Address;
}

pub struct TestTcpAddressMaker {}

impl RandomAddressMaker for TestTcpAddressMaker {
    type Address = SocketAddr;

    fn new() -> Self::Address {
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
        SocketAddr::new(IpAddr::V6(ip), rng.gen())
    }
}

pub struct TestChannelAddressMaker {}

impl RandomAddressMaker for TestChannelAddressMaker {
    type Address = u32;

    fn new() -> Self::Address {
        let mut rng = make_pseudo_rng();
        rng.gen()
    }
}

/// Can be used in tests only, will panic in case of errors
pub async fn connect_services<T>(
    conn1: &mut T::ConnectivityHandle,
    conn2: &mut T::ConnectivityHandle,
) -> (T::Address, PeerInfo<T>, PeerInfo<T>)
where
    T: NetworkingService + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr = timeout(Duration::from_secs(5), conn2.local_addresses())
        .await
        .expect("local address fetch not to timeout")
        .unwrap();
    conn1.connect(addr[0].clone()).await.expect("dial to succeed");

    let (address, peer_info1) = match timeout(Duration::from_secs(5), conn2.poll_next()).await {
        Ok(event) => match event.unwrap() {
            ConnectivityEvent::InboundAccepted { address, peer_info } => (address, peer_info),
            event => panic!("expected `InboundAccepted`, got {event:?}"),
        },
        Err(_err) => panic!("did not receive `InboundAccepted` in time"),
    };

    let peer_info2 = match timeout(Duration::from_secs(5), conn1.poll_next()).await {
        Ok(event) => match event.unwrap() {
            ConnectivityEvent::OutboundAccepted {
                address: _,
                peer_info,
            } => peer_info,
            event => panic!("expected `OutboundAccepted`, got {event:?}"),
        },
        Err(_err) => panic!("did not receive `OutboundAccepted` in time"),
    };

    (address, peer_info1, peer_info2)
}

/// Return first event that is accepted by predicate.
///
/// Used to skip events that are not of interest or that are different between backends
/// (for example ConnectivityEvent::Discovered).
/// Can be used in tests only, will panic in case of errors.
pub async fn filter_connectivity_event<T, F>(
    conn: &mut T::ConnectivityHandle,
    predicate: F,
) -> crate::Result<ConnectivityEvent<T>>
where
    T: NetworkingService,
    T::ConnectivityHandle: ConnectivityService<T>,
    F: Fn(&crate::Result<ConnectivityEvent<T>>) -> bool,
{
    loop {
        let result = timeout(Duration::from_secs(10), conn.poll_next())
            .await
            .expect("unexpected timeout receiving connectivity event");
        if predicate(&result) {
            return result;
        }
    }
}
