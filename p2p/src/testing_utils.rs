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
    collections::BTreeSet,
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use common::primitives::user_agent::mintlayer_core_user_agent;
use crypto::random::Rng;
use futures::Future;
use logging::log;
use p2p_types::socket_address::SocketAddress;
use tokio::time::timeout;

use crate::{
    ban_config::BanConfig,
    config::P2pConfig,
    net::{
        default_backend::transport::{
            MpscChannelTransport, NoiseEncryptionAdapter, NoiseTcpTransport, TcpTransportSocket,
            TransportListener, TransportSocket,
        },
        types::{ConnectivityEvent, PeerInfo},
        ConnectivityService, NetworkingService,
    },
    peer_manager::{
        config::PeerManagerConfig,
        peerdb::{config::PeerDbConfig, storage_impl::PeerDbStorageImpl},
    },
    protocol::{ProtocolVersion, SupportedProtocolVersion},
};

/// A protocol version for use in tests that just need some valid value for it.
// TODO: ideally, tests that use this constant should call for_each_protocol_version instead
// and thus check all available versions.
pub const TEST_PROTOCOL_VERSION: SupportedProtocolVersion = SupportedProtocolVersion::V2;

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
        "127.0.0.1:0".parse().unwrap()
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

impl TestTransportChannel {
    pub fn make_transport_with_local_addr_in_group(
        addr_group_idx: u32,
        addr_group_bit_offset: u32,
    ) -> MpscChannelTransport {
        MpscChannelTransport::new_with_addr_in_group(addr_group_idx, addr_group_bit_offset)
    }
}

pub fn make_transport_with_local_addr_in_group(
    group_idx: u32,
) -> <TestTransportChannel as TestTransportMaker>::Transport {
    let group_bits = crate::peer_manager::address_groups::IPV4_GROUP_BYTES * 8;

    TestTransportChannel::make_transport_with_local_addr_in_group(
        // Make sure that the most significant byte of the address is non-zero
        // (all 0.x.x.x addresses get into AddressGroup::Private, but we want all
        // addresses to be in different address groups).
        group_idx + (1 << (group_bits - 1)),
        group_bits as u32,
    )
}

pub struct TestTransportNoise {}

impl TestTransportMaker for TestTransportNoise {
    type Transport = NoiseTcpTransport;

    fn make_transport() -> Self::Transport {
        let base_transport = TcpTransportSocket::new();
        NoiseTcpTransport::new(NoiseEncryptionAdapter::gen_new, base_transport)
    }

    fn make_address() -> SocketAddress {
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

    pub fn new_random_address(rng: &mut impl Rng) -> SocketAddress {
        let ip = Self::new_random_ipv6_addr(rng);
        SocketAddress::new(SocketAddr::new(IpAddr::V6(ip), rng.gen()))
    }
}

pub struct TestChannelAddressMaker {}

/// Connect the node represented by conn1 to the first listening address of the node represented
/// by conn2.
/// Can be used in tests only, will panic in case of errors.
pub async fn connect_services<T>(
    conn1: &mut T::ConnectivityHandle,
    conn2: &mut T::ConnectivityHandle,
) -> (SocketAddress, PeerInfo, PeerInfo)
where
    T: NetworkingService + Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let conn2_local_addrs = conn2.local_addresses();
    conn1.connect(conn2_local_addrs[0], None).expect("dial to succeed");

    let (peer1_address, peer1_info) = match timeout(Duration::from_secs(5), conn2.poll_next()).await
    {
        Ok(event) => match event.unwrap() {
            ConnectivityEvent::InboundAccepted {
                peer_address,
                bind_address: _,
                peer_info,
                node_address_as_seen_by_peer: _,
            } => (peer_address, peer_info),
            event => panic!("expected `InboundAccepted`, got {event:?}"),
        },
        Err(_err) => panic!("did not receive `InboundAccepted` in time"),
    };

    let peer2_info = match timeout(Duration::from_secs(5), conn1.poll_next()).await {
        Ok(event) => match event.unwrap() {
            ConnectivityEvent::OutboundAccepted {
                peer_address: _,
                bind_address: _,
                peer_info,
                node_address_as_seen_by_peer: _,
            } => peer_info,
            event => panic!("expected `OutboundAccepted`, got {event:?}"),
        },
        Err(_err) => panic!("did not receive `OutboundAccepted` in time"),
    };

    (peer1_address, peer1_info, peer2_info)
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

pub fn test_p2p_config() -> P2pConfig {
    P2pConfig {
        bind_addresses: Default::default(),
        socks5_proxy: Default::default(),
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        whitelisted_addresses: Default::default(),
        ban_config: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        peer_manager_config: Default::default(),
        protocol_config: Default::default(),
    }
}

pub fn test_p2p_config_with_peer_mgr_config(peer_manager_config: PeerManagerConfig) -> P2pConfig {
    P2pConfig {
        peer_manager_config,

        bind_addresses: Default::default(),
        socks5_proxy: Default::default(),
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        whitelisted_addresses: Default::default(),
        ban_config: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        protocol_config: Default::default(),
    }
}

pub fn test_p2p_config_with_peer_db_config(peerdb_config: PeerDbConfig) -> P2pConfig {
    test_p2p_config_with_peer_mgr_config(PeerManagerConfig {
        peerdb_config,

        max_inbound_connections: Default::default(),
        preserved_inbound_count_address_group: Default::default(),
        preserved_inbound_count_ping: Default::default(),
        preserved_inbound_count_new_blocks: Default::default(),
        preserved_inbound_count_new_transactions: Default::default(),
        outbound_full_relay_count: Default::default(),
        outbound_full_relay_extra_count: Default::default(),
        outbound_block_relay_count: Default::default(),
        outbound_block_relay_extra_count: Default::default(),
        outbound_block_relay_connection_min_age: Default::default(),
        outbound_full_relay_connection_min_age: Default::default(),
        stale_tip_time_diff: Default::default(),
        main_loop_tick_interval: Default::default(),
        enable_feeler_connections: Default::default(),
        feeler_connections_interval: Default::default(),
        force_dns_query_if_no_global_addresses_known: Default::default(),
        allow_same_ip_connections: Default::default(),
    })
}

pub fn test_p2p_config_with_ban_config(ban_config: BanConfig) -> P2pConfig {
    P2pConfig {
        ban_config,

        bind_addresses: Default::default(),
        socks5_proxy: Default::default(),
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        whitelisted_addresses: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        peer_manager_config: Default::default(),
        protocol_config: Default::default(),
    }
}

pub fn test_peer_mgr_config_with_no_auto_outbound_connections() -> PeerManagerConfig {
    PeerManagerConfig {
        outbound_block_relay_count: 0.into(),
        outbound_block_relay_extra_count: 0.into(),
        outbound_full_relay_count: 0.into(),
        outbound_full_relay_extra_count: 0.into(),
        enable_feeler_connections: false.into(),

        outbound_block_relay_connection_min_age: Default::default(),
        peerdb_config: Default::default(),
        preserved_inbound_count_address_group: Default::default(),
        preserved_inbound_count_ping: Default::default(),
        preserved_inbound_count_new_blocks: Default::default(),
        preserved_inbound_count_new_transactions: Default::default(),
        max_inbound_connections: Default::default(),
        outbound_full_relay_connection_min_age: Default::default(),
        stale_tip_time_diff: Default::default(),
        main_loop_tick_interval: Default::default(),
        feeler_connections_interval: Default::default(),
        allow_same_ip_connections: Default::default(),
        force_dns_query_if_no_global_addresses_known: Default::default(),
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

pub async fn for_each_protocol_version<Func, Res>(func: Func)
where
    Func: Fn(ProtocolVersion) -> Res,
    Res: Future<Output = ()>,
{
    for version in enum_iterator::all::<SupportedProtocolVersion>() {
        log::info!("---------- Testing protocol version {version:?} ----------");
        func(version.into()).await;
    }
}
