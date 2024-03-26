// Copyright (c) 2021-2023 RBB S.r.l
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

use std::sync::Arc;

use rstest::rstest;

use common::{
    chain::{self, ChainConfig},
    primitives::user_agent::mintlayer_core_user_agent,
};
use crypto::random::Rng;
use p2p_test_utils::{expect_recv, P2pBasicTestTimeGetter};
use p2p_types::{peer_address::PeerAddress, socket_address::SocketAddress};
use test_utils::{
    assert_matches_return_val,
    random::{make_seedable_rng, Seed},
};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::{
    config::{NodeType, P2pConfig},
    message::AddrListResponse,
    net::{
        default_backend::{
            transport::TcpTransportSocket,
            types::{Command, Message},
            DefaultNetworkingService,
        },
        types::{PeerInfo, Role},
        ConnectivityService, NetworkingService,
    },
    peer_manager::{
        addr_list_response_cache,
        peerdb::{
            address_tables::table::test_utils::make_non_colliding_addresses, storage::PeerDbStorage,
        },
        PeerManager,
    },
    protocol::ProtocolConfig,
    testing_utils::{TestAddressMaker, TEST_PROTOCOL_VERSION},
    types::peer_id::PeerId,
};

use super::make_standalone_peer_manager;

// Note: addr list requests are only handled for inbound peers, so we only test this variant.

type TestNetworkingService = DefaultNetworkingService<TcpTransportSocket>;

#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn basic_test(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let bind_address12 = TestAddressMaker::new_random_address(&mut rng);
    let bind_address3 = TestAddressMaker::new_random_address(&mut rng);

    let chain_config = Arc::new(chain::config::create_unit_test_config());
    let p2p_config = Arc::new(make_p2p_config());
    let time_getter = P2pBasicTestTimeGetter::new();

    let (mut peer_mgr, mut cmd_receiver) =
        setup_peer_mgr(&chain_config, &p2p_config, &time_getter, &mut rng);

    let peer1_address = TestAddressMaker::new_random_address(&mut rng);
    let (peer1_id, peer1_info) = make_new_peer(&chain_config);
    accept_conn(
        &mut peer_mgr,
        &mut cmd_receiver,
        peer1_address,
        bind_address12,
        &peer1_info,
    )
    .await;
    assert_eq!(peer_mgr.peers.len(), 1);

    peer_mgr.handle_addr_list_request(peer1_id);
    let cmd = expect_recv!(cmd_receiver);
    let addresses_for_peer1 = expect_addresses_from(cmd, peer1_id);

    // Remove the addresses from the db
    for address in &addresses_for_peer1 {
        peer_mgr.peerdb.remove_address(
            &SocketAddress::from_peer_address(address, *p2p_config.allow_discover_private_ips)
                .unwrap(),
        );
    }

    // Close and re-open the connection to peer1.
    peer_mgr.connection_closed(peer1_id);
    assert_eq!(peer_mgr.peers.len(), 0);
    accept_conn(
        &mut peer_mgr,
        &mut cmd_receiver,
        peer1_address,
        bind_address12,
        &peer1_info,
    )
    .await;
    assert_eq!(peer_mgr.peers.len(), 1);

    // Addr list request should return the same list.
    peer_mgr.handle_addr_list_request(peer1_id);
    let cmd = expect_recv!(cmd_receiver);
    let addresses_for_peer1_again = expect_addresses_from(cmd, peer1_id);
    assert_eq!(addresses_for_peer1, addresses_for_peer1_again);

    // Accept connection from another peer with the same bind address.
    let peer2_address = TestAddressMaker::new_random_address(&mut rng);
    let (peer2_id, peer2_info) = make_new_peer(&chain_config);
    accept_conn(
        &mut peer_mgr,
        &mut cmd_receiver,
        peer2_address,
        bind_address12,
        &peer2_info,
    )
    .await;
    assert_eq!(peer_mgr.peers.len(), 2);

    // Addr list request should return the same list.
    peer_mgr.handle_addr_list_request(peer2_id);
    let cmd = expect_recv!(cmd_receiver);
    let addresses_for_peer2 = expect_addresses_from(cmd, peer2_id);
    assert_eq!(addresses_for_peer1, addresses_for_peer2);

    // Accept connection from another peer with a different bind address.
    let peer3_address = TestAddressMaker::new_random_address(&mut rng);
    let (peer3_id, peer3_info) = make_new_peer(&chain_config);
    accept_conn(
        &mut peer_mgr,
        &mut cmd_receiver,
        peer3_address,
        bind_address3,
        &peer3_info,
    )
    .await;
    assert_eq!(peer_mgr.peers.len(), 3);

    // Addr list request should be different this time.
    peer_mgr.handle_addr_list_request(peer3_id);
    let cmd = expect_recv!(cmd_receiver);
    let addresses_for_peer3 = expect_addresses_from(cmd, peer3_id);
    assert_ne!(addresses_for_peer3, addresses_for_peer1);

    // Advance the time, so that the cache expires.
    time_getter.advance_time(addr_list_response_cache::EXPIRATION_INTERVAL_MAX);

    // Close and re-open the connections, using the samer bind addresses.
    peer_mgr.connection_closed(peer1_id);
    peer_mgr.connection_closed(peer2_id);
    peer_mgr.connection_closed(peer3_id);
    assert_eq!(peer_mgr.peers.len(), 0);
    accept_conn(
        &mut peer_mgr,
        &mut cmd_receiver,
        peer1_address,
        bind_address12,
        &peer1_info,
    )
    .await;
    accept_conn(
        &mut peer_mgr,
        &mut cmd_receiver,
        peer2_address,
        bind_address12,
        &peer2_info,
    )
    .await;
    accept_conn(
        &mut peer_mgr,
        &mut cmd_receiver,
        peer3_address,
        bind_address3,
        &peer3_info,
    )
    .await;
    assert_eq!(peer_mgr.peers.len(), 3);

    // Addr list requests should return a new list.
    peer_mgr.handle_addr_list_request(peer1_id);
    let cmd = expect_recv!(cmd_receiver);
    let addresses_for_peer1_after_cache_exp_time = expect_addresses_from(cmd, peer1_id);
    assert_ne!(
        addresses_for_peer1,
        addresses_for_peer1_after_cache_exp_time
    );

    peer_mgr.handle_addr_list_request(peer2_id);
    let cmd = expect_recv!(cmd_receiver);
    let addresses_for_peer2_after_cache_exp_time = expect_addresses_from(cmd, peer2_id);
    assert_ne!(
        addresses_for_peer2,
        addresses_for_peer2_after_cache_exp_time
    );

    peer_mgr.handle_addr_list_request(peer3_id);
    let cmd = expect_recv!(cmd_receiver);
    let addresses_for_peer3_after_cache_exp_time = expect_addresses_from(cmd, peer3_id);
    assert_ne!(
        addresses_for_peer3,
        addresses_for_peer2_after_cache_exp_time
    );

    // Still, the new lists should be equal for peers 1 and 2 but different for peer 3.
    assert_eq!(
        addresses_for_peer1_after_cache_exp_time,
        addresses_for_peer2_after_cache_exp_time
    );
    assert_ne!(
        addresses_for_peer1_after_cache_exp_time,
        addresses_for_peer3_after_cache_exp_time
    );
}

fn make_p2p_config() -> P2pConfig {
    P2pConfig {
        protocol_config: ProtocolConfig {
            // Note: with the default value we'd have to switch off the extra test checks
            // in address tables, because the test would take forever to complete.
            max_addr_list_response_address_count: 10.into(),

            msg_header_count_limit: Default::default(),
            max_request_blocks_count: Default::default(),
            msg_max_locator_count: Default::default(),
            max_message_size: Default::default(),
            max_peer_tx_announcements: Default::default(),
        },

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
    }
}

fn setup_peer_mgr(
    chain_config: &Arc<ChainConfig>,
    p2p_config: &Arc<P2pConfig>,
    time_getter: &P2pBasicTestTimeGetter,
    rng: &mut impl Rng,
) -> (
    PeerManager<TestNetworkingService, impl PeerDbStorage>,
    UnboundedReceiver<Command>,
) {
    let (mut peer_mgr, _conn_event_sender, _peer_mgr_event_sender, cmd_receiver, _) =
        make_standalone_peer_manager(
            Arc::clone(chain_config),
            Arc::clone(p2p_config),
            // Note: technically, we should pass the bind addresses here, but since we don't
            // establish real connections, it doesn't really matter.
            vec![],
            time_getter.get_time_getter(),
        );

    let addresses_in_db = make_non_colliding_addresses(
        &[peer_mgr.peerdb.address_tables().new_addr_table()],
        *p2p_config.protocol_config.max_addr_list_response_address_count * 10,
        rng,
    );

    for address in addresses_in_db {
        peer_mgr.peerdb.peer_discovered(address);
    }

    (peer_mgr, cmd_receiver)
}

fn make_new_peer(chain_config: &ChainConfig) -> (PeerId, PeerInfo) {
    let id = PeerId::new();
    let info = PeerInfo {
        peer_id: id,
        protocol_version: TEST_PROTOCOL_VERSION,
        network: *chain_config.magic_bytes(),
        software_version: *chain_config.software_version(),
        user_agent: mintlayer_core_user_agent(),
        common_services: NodeType::Full.into(),
    };
    (id, info)
}

fn expect_addresses_from(cmd: Command, expected_peer_id: PeerId) -> Vec<PeerAddress> {
    assert_matches_return_val!(
        cmd,
        Command::SendMessage {
            peer_id,
            message: Message::AddrListResponse(AddrListResponse { addresses }),
        } if peer_id == expected_peer_id,
        addresses
    )
}

async fn accept_conn<T, S>(
    peer_mgr: &mut PeerManager<T, S>,
    cmd_receiver: &mut UnboundedReceiver<Command>,
    peer_addr: SocketAddress,
    bind_addr: SocketAddress,
    peer_info: &PeerInfo,
) where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    S: PeerDbStorage,
{
    peer_mgr.accept_connection(peer_addr, bind_addr, Role::Inbound, peer_info.clone(), None);
    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(
        cmd,
        Command::Accept {
            peer_id: peer_info.peer_id
        }
    );
}
