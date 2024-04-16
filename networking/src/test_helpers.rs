// Copyright (c) 2021-2024 RBB S.r.l
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

//! A module for test utilities that depend on `networking` and that are supposed to be used both
//! in `networking`'s unit tests and some other crates.
//! Note that under this scenario it's impossible to put it into a separate crate, because
//! `networking` would be compiled twice in that case and the two variants would be incompatible
//! with each other, producing errors like "`XXX` and `XXX` have similar names, but are actually
//! distinct types ... the crate `YYY` is compiled multiple times, possibly with different configurations".

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use randomness::Rng;

use crate::transport::{
    MpscChannelTransport, NoiseEncryptionAdapter, NoiseTcpTransport, TcpTransportSocket,
    TransportListener, TransportSocket,
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
    fn make_address() -> SocketAddr;
}

pub struct TestTransportTcp {}

impl TestTransportMaker for TestTransportTcp {
    type Transport = TcpTransportSocket;

    fn make_transport() -> Self::Transport {
        TcpTransportSocket::new()
    }

    fn make_address() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }
}

pub struct TestTransportChannel {}

impl TestTransportMaker for TestTransportChannel {
    type Transport = MpscChannelTransport;

    fn make_transport() -> Self::Transport {
        MpscChannelTransport::new()
    }

    fn make_address() -> SocketAddr {
        "0.0.0.0:0".parse().unwrap()
    }
}

pub struct TestTransportNoise {}

impl TestTransportMaker for TestTransportNoise {
    type Transport = NoiseTcpTransport;

    fn make_transport() -> Self::Transport {
        let base_transport = TcpTransportSocket::new();
        NoiseTcpTransport::new(NoiseEncryptionAdapter::gen_new, base_transport)
    }

    fn make_address() -> SocketAddr {
        TestTransportTcp::make_address()
    }
}

pub struct TestAddressMaker {}

impl TestAddressMaker {
    pub fn new_random_ipv6_addr(rng: &mut impl Rng) -> Ipv6Addr {
        Ipv6Addr::new(
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
        )
    }

    pub fn new_distinct_random_ipv6_addrs(count: usize, rng: &mut impl Rng) -> Vec<Ipv6Addr> {
        let mut addrs = BTreeSet::new();

        while addrs.len() < count {
            addrs.insert(Self::new_random_ipv6_addr(rng));
        }

        addrs.iter().copied().collect()
    }

    pub fn new_random_ipv4_addr(rng: &mut impl Rng) -> Ipv4Addr {
        Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen())
    }

    pub fn new_distinct_random_ipv4_addrs(count: usize, rng: &mut impl Rng) -> Vec<Ipv4Addr> {
        let mut addrs = BTreeSet::new();

        while addrs.len() < count {
            addrs.insert(Self::new_random_ipv4_addr(rng));
        }

        addrs.iter().copied().collect()
    }

    pub fn new_random_address(rng: &mut impl Rng) -> SocketAddr {
        let ip = Self::new_random_ipv6_addr(rng);
        SocketAddr::new(IpAddr::V6(ip), rng.gen())
    }
}

pub async fn get_two_connected_sockets<A, T>() -> (T::Stream, T::Stream)
where
    A: TestTransportMaker<Transport = T>,
    T: TransportSocket,
{
    let transport = A::make_transport();
    let addr = A::make_address();
    let mut server = transport.bind(vec![addr]).await.unwrap();
    let peer_fut = transport.connect(server.local_addresses().unwrap()[0]);

    let (res1, res2) = tokio::join!(server.accept(), peer_fut);
    (res1.unwrap().0, res2.unwrap())
}
