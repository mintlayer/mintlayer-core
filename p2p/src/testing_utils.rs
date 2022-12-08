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

use libp2p::Multiaddr;
use std::net::SocketAddr;

/// An interface for creating test transports and addresses.
///
/// This abstraction layer is needed to uniformly create transports and addresses
/// in the tests for different mocks transport implementations.
pub trait TestTransport {
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

pub struct TestTransportLibp2p {}

impl TestTransport for TestTransportLibp2p {
    type Transport = crate::net::libp2p::Libp2pTransport;

    type Address = Multiaddr;

    fn make_transport() -> Self::Transport {
        let p2p_config = Default::default();
        crate::net::libp2p::make_transport(&p2p_config)
    }

    fn make_address() -> Self::Address {
        "/ip6/::1/tcp/0".parse().expect("valid address")
    }
}

pub struct TestTransportTcp {}

impl TestTransport for TestTransportTcp {
    type Transport = crate::net::mock::transport::TcpTransportSocket;

    type Address = SocketAddr;

    fn make_transport() -> Self::Transport {
        crate::net::mock::transport::TcpTransportSocket::new()
    }

    fn make_address() -> Self::Address {
        "[::1]:0".parse().expect("valid address")
    }
}

pub struct TestTransportChannel {}

impl TestTransport for TestTransportChannel {
    type Transport = crate::net::mock::transport::MockChannelTransport;

    type Address = u64;

    fn make_transport() -> Self::Transport {
        crate::net::mock::transport::MockChannelTransport::new()
    }

    fn make_address() -> Self::Address {
        0
    }
}

pub struct TestTransportNoise {}

impl TestTransport for TestTransportNoise {
    type Transport = crate::net::mock::transport::NoiseTcpTransport;

    type Address = SocketAddr;

    fn make_transport() -> Self::Transport {
        let stream_adapter = crate::net::mock::transport::NoiseEncryptionAdapter::gen_new();
        let base_transport = crate::net::mock::transport::TcpTransportSocket::new();
        crate::net::mock::transport::NoiseTcpTransport::new(stream_adapter, base_transport)
    }

    fn make_address() -> Self::Address {
        TestTransportTcp::make_address()
    }
}
