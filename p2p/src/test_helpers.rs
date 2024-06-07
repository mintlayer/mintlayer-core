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

//! A module for test utilities that depend on `p2p` and that are supposed to be used both
//! in `p2p`'s unit tests and some other crates.
//! Note that under this scenario it's impossible to put it into a separate crate (such as p2p-test-utils),
//! because `p2p` would be compiled twice in that case and the two variants would be incompatible
//! with each other, producing errors like "`XXX` and `XXX` have similar names, but are actually
//! distinct types ... the crate `YYY` is compiled multiple times, possibly with different configurations".

use std::{fmt::Debug, net::Ipv4Addr, time::Duration};

use futures::Future;
use tokio::time::timeout;

use common::primitives::user_agent::mintlayer_core_user_agent;
use logging::log;
use networking::transport::MpscChannelTransport;

use crate::{
    ban_config::BanConfig,
    config::P2pConfig,
    net::{
        types::{ConnectivityEvent, PeerInfo},
        ConnectivityService, NetworkingService,
    },
    peer_manager::{
        self,
        config::PeerManagerConfig,
        peerdb::{config::PeerDbConfig, storage_impl::PeerDbStorageImpl},
    },
    protocol::{ProtocolVersion, SupportedProtocolVersion},
    types::socket_address::SocketAddress,
};

/// A protocol version for use in tests that just need some valid value for it.
// TODO: ideally, tests that use this constant should call for_each_protocol_version instead
// and thus check all available versions.
pub const TEST_PROTOCOL_VERSION: SupportedProtocolVersion = SupportedProtocolVersion::V2;

/// Create a new MpscChannelTransport with a local address in the specified "group", which is
/// represented by an integer.
///
/// Internally, the address group is represented by a specific number of most significant bits
/// in the ip address; this function basically puts the passed addr_group_idx into that bit range.
///
/// The function will also set the resulting address' highest bit to ensure that it doesn't end up
/// in AddressGroup::Private (to which all 0.x.x.x addresses are mapped).
pub fn make_transport_with_local_addr_in_group(addr_group_idx: u32) -> MpscChannelTransport {
    let addr_group_bits = peer_manager::address_groups::IPV4_GROUP_BYTES * 8;
    let addr_group_bit_offset = 32 - addr_group_bits;
    // Set the highest bit.
    let addr_group = addr_group_idx | (1 << (addr_group_bits - 1));

    let next_addr_as_u32 = MpscChannelTransport::next_local_address_as_u32();
    assert!((next_addr_as_u32 as u64) < (1_u64 << addr_group_bit_offset));

    let addr_group = (addr_group as u64) << addr_group_bit_offset;
    assert!(addr_group <= u32::MAX as u64);

    let local_address: Ipv4Addr = (next_addr_as_u32 + addr_group as u32).into();
    MpscChannelTransport::new_with_local_address(local_address.into())
}

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

pub fn peerdb_inmemory_store() -> PeerDbStorageImpl<storage_inmemory::InMemory> {
    let storage = storage_inmemory::InMemory::new();
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
