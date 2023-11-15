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

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use chainstate::BlockSource;
use common::{
    chain::{config::ChainType, Block, ChainConfig, Destination, NetUpgrades},
    primitives::{user_agent::mintlayer_core_user_agent, Idable},
};
use logging::log;
use p2p_test_utils::P2pBasicTestTimeGetter;
use p2p_types::socket_address::SocketAddress;
use test_utils::random::Seed;

use crate::{
    config::P2pConfig,
    net::types::PeerRole,
    peer_manager::{
        self, address_groups::AddressGroup, stale_tip_time_diff, ConnectionCountLimits,
        PEER_MGR_DNS_RELOAD_INTERVAL, PEER_MGR_HEARTBEAT_INTERVAL_MAX,
        PEER_MGR_HEARTBEAT_INTERVAL_MIN,
    },
    sync::test_helpers::make_new_block,
    testing_utils::{TestTransportChannel, TestTransportMaker, TEST_PROTOCOL_VERSION},
    tests::helpers::{timeout, PeerManagerNotification, TestNode, TestNodeGroup},
};

// In these tests we want to create nodes in different "address groups" to ensure that
// the maximum number of connections can be established (peer manager normally won't allow more
// than 1 outbound connection per address group). To do so we must use ip addresses with distinct
// higher bytes; only the channel-based transport allows to use arbitrary ip addresses, so we
// have to use it.
type Transport = <TestTransportChannel as TestTransportMaker>::Transport;

// Test scenario:
// 1) Create a set of nodes; the number of nodes is equal to the maximum number of outbound
// connections that a single node can establish plus 1.
// 2) Announce nodes' addresses via the dns seed; the nodes should connect to each other.
// 3) Wait for one hour; the initial block is now stale, but the nodes are still connected
// to each other.
// 4) Start a new node that has a fresh block; announce its address via the dns seed;
// the old nodes should find the new one; some of them should establish an outbound connection
// to it; eventually, all old nodes should receive the fresh block.
//
// The test exists in several variants, which are controlled by the parameters:
// 1) start_in_ibd - if true, the initial set of nodes will only have the genesis block at the start,
// i.e. they all will start in IBD; otherwise they'll start with a fresh block.
// 2) use_extra_block_relay_peers - if true, 1 extra block relay connection will be enabled while
// extra full relay connections will be disabled; otherwise it'll be vice versa.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_discovery_on_stale_tip(
    #[case] seed: Seed,
    #[values(true, false)] start_in_ibd: bool,
    #[values(true, false)] use_extra_block_relay_peers: bool,
) {
    timeout(peer_discovery_on_stale_tip_impl(
        seed,
        start_in_ibd,
        use_extra_block_relay_peers,
    ))
    .await;
}

async fn peer_discovery_on_stale_tip_impl(
    seed: Seed,
    start_in_ibd: bool,
    use_extra_block_relay_peers: bool,
) {
    let mut rng = test_utils::random::make_seedable_rng(seed);
    let time_getter = P2pBasicTestTimeGetter::new();
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());

    // The sum of these values plus the "extra_count" values is the number
    // of nodes that the tests will create.
    // We reduce the default values to make the tests less "heavy".
    let outbound_full_relay_conn_count = 2;
    let outbound_block_relay_conn_count = 0;
    let (outbound_full_relay_extra_conn_count, outbound_block_relay_extra_conn_count) =
        if use_extra_block_relay_peers {
            (0, 1)
        } else {
            (1, 0)
        };
    let conn_count_limits = ConnectionCountLimits {
        outbound_full_relay_count: outbound_full_relay_conn_count.into(),
        outbound_block_relay_count: outbound_block_relay_conn_count.into(),

        outbound_full_relay_extra_count: outbound_full_relay_extra_conn_count.into(),
        outbound_block_relay_extra_count: outbound_block_relay_extra_conn_count.into(),

        // These values will only matter if max_inbound_connections is low enough.
        // Also, we don't really want to make inbound peer eviction more aggressive,
        // because it may make the tests more fragile, so we use the defaults.
        preserved_inbound_count_address_group: Default::default(),
        preserved_inbound_count_ping: Default::default(),
        preserved_inbound_count_new_blocks: Default::default(),
        preserved_inbound_count_new_transactions: Default::default(),

        max_inbound_connections: Default::default(),
    };
    let p2p_config = Arc::new(make_p2p_config(conn_count_limits));

    let nodes_count = p2p_config.connection_count_limits.outbound_full_and_block_relay_count()
        + *p2p_config.connection_count_limits.outbound_full_relay_extra_count
        + *p2p_config.connection_count_limits.outbound_block_relay_extra_count
        + 1;
    let mut nodes = Vec::with_capacity(nodes_count);

    let initial_block = if start_in_ibd {
        None
    } else {
        Some(make_new_block(
            &chain_config,
            None,
            &time_getter.get_time_getter(),
            &mut rng,
        ))
    };

    for i in 0..nodes_count {
        nodes.push(
            start_node(
                &time_getter,
                &chain_config,
                &p2p_config,
                i + 1,
                initial_block.clone(),
            )
            .await,
        );
    }

    let node_group = TestNodeGroup::new(nodes);
    let node_addresses = node_group.get_adresses();

    let address_groups: BTreeSet<_> = node_addresses
        .iter()
        .map(|addr| AddressGroup::from_peer_address(&addr.as_peer_address()))
        .collect();
    // Sanity check - all addresses belong to separate address groups
    assert_eq!(address_groups.len(), nodes_count);

    node_group.set_dns_seed_addresses(&node_addresses);

    time_getter.advance_time(PEER_MGR_DNS_RELOAD_INTERVAL);

    // Wait until the maximum number of outbound connections is established.
    wait_for_max_outbound_connections(&node_group).await;

    // Advance the time by 1 hour
    log::debug!("Advancing time by 1 hour");
    time_getter.advance_time(Duration::from_secs(60 * 60));

    // All the connections must still be in place
    node_group.assert_outbound_conn_count_maximums_reached().await;

    // Start a new node that would produce a block.
    let new_node_idx = node_group.nodes().len() + 1;
    let new_node = start_node(
        &time_getter,
        &chain_config,
        &p2p_config,
        new_node_idx,
        initial_block.clone(),
    )
    .await;
    let new_node_addr = *new_node.local_address();

    let new_block = make_new_block(
        &chain_config,
        initial_block.as_ref(),
        &time_getter.get_time_getter(),
        &mut rng,
    );
    let new_block_id = new_block.get_id();

    new_node
        .chainstate()
        .call_mut(move |cs| {
            cs.process_block(new_block, BlockSource::Local).unwrap();
        })
        .await
        .unwrap();

    // Announce the node through the dns seed.
    let mut node_addresses = node_addresses;
    node_addresses.push(new_node_addr);
    node_group.set_dns_seed_addresses(&node_addresses);

    // Wait for some connections to the new node to be established.
    node_group_wait_for_connections_to(&node_group, new_node_addr, nodes_count / 2).await;

    // Wait for the new block to be propagated to all the nodes.
    node_group
        .wait_for_block_propagation_advance_time(
            nodes_count,
            new_block_id,
            PEER_MGR_HEARTBEAT_INTERVAL_MAX,
        )
        .await;

    log::debug!("shutting down");

    node_group.join().await;
    new_node.join().await;
}

// Test scenario:
// 1) Create a node with 1 for both outbound_full_relay_count and outbound_full_relay_extra_count.
// Also create a bunch of extra nodes that can only create inbound connections.
// All nodes will start with a fresh block, so they won't be in IBD.
// 2) Make the "normal" node connect to one of the extra nodes; give it some time to be able
// to connect to more nodes if it wants to. It shouldn't connect to any other nodes though.
// 3) Advance time so that the tip becomes stale. The "normal" node should now try to establish
// an outbound full relay connection to each of the extra nodes. But the number of connections
// at any given point should not exceed outbound_full_relay_count + outbound_full_relay_extra_count.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_full_relay_connections_on_stale_tip(#[case] seed: Seed) {
    timeout(new_full_relay_connections_on_stale_tip_impl(seed)).await;
}

async fn new_full_relay_connections_on_stale_tip_impl(seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);
    let time_getter = P2pBasicTestTimeGetter::new();
    let start_time = time_getter.get_time_getter().get_time();
    let chain_config = Arc::new(
        common::chain::config::Builder::new(ChainType::Testnet)
            .consensus_upgrades(NetUpgrades::unit_tests())
            .genesis_unittest(Destination::AnyoneCanSpend)
            // Note: this will affect stale_tip_time_diff
            .target_block_spacing(Duration::from_secs(60 * 30))
            .build(),
    );
    let stale_tip_time_diff = stale_tip_time_diff(&chain_config);

    let main_node_conn_count_limits = ConnectionCountLimits {
        outbound_full_relay_count: 1.into(),
        outbound_full_relay_extra_count: 1.into(),

        outbound_block_relay_count: 0.into(),
        outbound_block_relay_extra_count: 0.into(),

        preserved_inbound_count_address_group: Default::default(),
        preserved_inbound_count_ping: Default::default(),
        preserved_inbound_count_new_blocks: Default::default(),
        preserved_inbound_count_new_transactions: Default::default(),

        max_inbound_connections: Default::default(),
    };
    let main_node_p2p_config = Arc::new(make_p2p_config(main_node_conn_count_limits));

    // The extra nodes won't create outbound connections.
    let extra_nodes_conn_count_limits = ConnectionCountLimits {
        outbound_full_relay_count: 0.into(),
        outbound_full_relay_extra_count: 0.into(),

        outbound_block_relay_count: 0.into(),
        outbound_block_relay_extra_count: 0.into(),

        preserved_inbound_count_address_group: Default::default(),
        preserved_inbound_count_ping: Default::default(),
        preserved_inbound_count_new_blocks: Default::default(),
        preserved_inbound_count_new_transactions: Default::default(),

        max_inbound_connections: Default::default(),
    };
    let extra_nodes_p2p_config = Arc::new(make_p2p_config(extra_nodes_conn_count_limits));

    let extra_nodes_count = 10;
    let mut extra_nodes = Vec::with_capacity(extra_nodes_count);

    let initial_block = make_new_block(
        &chain_config,
        None,
        &time_getter.get_time_getter(),
        &mut rng,
    );

    let mut main_node = start_node(
        &time_getter,
        &chain_config,
        &main_node_p2p_config,
        0,
        Some(initial_block.clone()),
    )
    .await;
    let main_node_address = *main_node.local_address();
    log::debug!("main_node_address = {main_node_address}");

    for i in 0..extra_nodes_count {
        extra_nodes.push(
            start_node(
                &time_getter,
                &chain_config,
                &extra_nodes_p2p_config,
                i + 1,
                Some(initial_block.clone()),
            )
            .await,
        );
    }

    let extra_nodes_group = TestNodeGroup::new(extra_nodes);
    let extra_nodes_addresses = extra_nodes_group.get_adresses();

    let address_groups: BTreeSet<_> = extra_nodes_addresses
        .iter()
        .chain(std::iter::once(&main_node_address))
        .map(|addr| AddressGroup::from_peer_address(&addr.as_peer_address()))
        .collect();
    // Sanity check - all addresses belong to separate address groups
    assert_eq!(address_groups.len(), extra_nodes_count + 1);

    // First, announce only one extra node and make sure the main node makes a OutboundFullRelay
    // connection to it.
    main_node.set_dns_seed_addresses(vec![extra_nodes_addresses[0]]);
    time_getter.advance_time(PEER_MGR_DNS_RELOAD_INTERVAL);

    node_wait_for_connection_to(&main_node, &time_getter, extra_nodes_addresses[0]).await;
    main_node
        .assert_connected_to(&[(extra_nodes_addresses[0], PeerRole::OutboundFullRelay)])
        .await;

    let all_dns_addresses = {
        // Note: since full relay nodes can exchange addresses, the main node may receive its own
        // address eventually and attempt to connect to itself. I.e. we have to deal with
        // self-connections when making assertions below anyway. So, let's announce main_node_address
        // from the very beginning to make self-connections more deterministic.
        let mut addresses = extra_nodes_addresses.clone();
        addresses.push(main_node_address);
        addresses
    };
    // Now announce all extra nodes.
    main_node.set_dns_seed_addresses(all_dns_addresses);
    time_getter.advance_time(PEER_MGR_DNS_RELOAD_INTERVAL);

    // Wait for a while, giving main node's peer manager time to connect to other nodes
    // (which it shouldn't do).
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        time_getter.advance_time(PEER_MGR_HEARTBEAT_INTERVAL_MAX);
    }

    // Sanity check - the tip is not stale yet
    let cur_time_diff = (time_getter.get_time_getter().get_time() - start_time).unwrap();
    log::debug!("cur_time_diff = {cur_time_diff:?}, stale_tip_time_diff = {stale_tip_time_diff:?}");
    assert!(cur_time_diff < stale_tip_time_diff);

    // We're still connected to the same one node.
    main_node
        .assert_connected_to(&[(extra_nodes_addresses[0], PeerRole::OutboundFullRelay)])
        .await;

    // Advance the time by 2 hours
    log::debug!("Advancing time by 2 hours");
    time_getter.advance_time(Duration::from_secs(60 * 60 * 2));

    // Sanity check - the tip is now stale
    let cur_time_diff = (time_getter.get_time_getter().get_time() - start_time).unwrap();
    log::debug!("cur_time_diff = {cur_time_diff:?}");
    assert!(cur_time_diff >= stale_tip_time_diff);

    let mut tried_connections = BTreeSet::new();
    tried_connections.insert(extra_nodes_addresses[0]);

    // Wait until the main node has tried connecting to all of the extra nodes.
    while tried_connections.len() < extra_nodes_addresses.len() {
        if let Some(notification) = main_node.try_recv_peer_mgr_notification() {
            if let PeerManagerNotification::ConnectionAccepted { address, peer_role } = notification
            {
                log::debug!("Connection accepted from {address}, role is {peer_role:?}");

                if address.socket_addr().ip() != main_node_address.socket_addr().ip() {
                    assert_eq!(peer_role, PeerRole::OutboundFullRelay);
                    tried_connections.insert(address);

                    // Make sure that at any given time the total number of outbound full relay connections
                    // is not bigger than outbound_full_relay_count plus outbound_full_relay_extra_count.
                    main_node.assert_outbound_conn_count_within_limits().await;

                    log::debug!(
                        "Got {} connections out of {}",
                        tried_connections.len(),
                        extra_nodes_count
                    );
                }
            }
        } else {
            // When the tip is stale, heartbeat should happen at the minimum interval.
            time_getter.advance_time(PEER_MGR_HEARTBEAT_INTERVAL_MIN);
        }
    }

    extra_nodes_group.join().await;
    main_node.join().await;
}

pub fn make_p2p_config(connection_count_limits: ConnectionCountLimits) -> P2pConfig {
    let several_hours = Duration::from_secs(60 * 60 * 5);

    P2pConfig {
        // Note: these tests move mocked time forward by 1 or 2 hours once and by smaller intervals
        // multiple times; because of this, nodes may see each other as dead or as having invalid
        // clocks and disconnect each other. To avoid this, we specify artificially large timeouts
        // and clock diff.
        ping_timeout: several_hours.into(),
        max_clock_diff: several_hours.into(),
        sync_stalling_timeout: several_hours.into(),

        connection_count_limits,
        bind_addresses: Default::default(),
        socks5_proxy: Default::default(),
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        ping_check_period: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        protocol_config: Default::default(),
    }
}

fn make_transport_with_local_addr_in_group(
    group_idx: u32,
) -> <TestTransportChannel as TestTransportMaker>::Transport {
    let group_bits = peer_manager::address_groups::IPV4_GROUP_BYTES * 8;

    TestTransportChannel::make_transport_with_local_addr_in_group(
        // Make sure that the most significant byte of the address is non-zero
        // (all 0.x.x.x addresses get into AddressGroup::Private, but we want all
        // addresses to be in different address groups).
        group_idx + (1 << (group_bits - 1)),
        group_bits as u32,
    )
}

async fn start_node(
    time_getter: &P2pBasicTestTimeGetter,
    chain_config: &Arc<ChainConfig>,
    p2p_config: &Arc<P2pConfig>,
    node_index: usize,
    initial_block: Option<Block>,
) -> TestNode<Transport> {
    let node = TestNode::<Transport>::start(
        time_getter.clone(),
        Arc::clone(chain_config),
        Arc::clone(p2p_config),
        make_transport_with_local_addr_in_group(node_index as u32),
        TestTransportChannel::make_address(),
        TEST_PROTOCOL_VERSION.into(),
    )
    .await;

    if let Some(block) = initial_block {
        node.chainstate()
            .call_mut(move |cs| {
                cs.process_block(block, BlockSource::Local).unwrap();
            })
            .await
            .unwrap();
    }

    node
}

async fn wait_for_max_outbound_connections(node_group: &TestNodeGroup<Transport>) {
    for node in node_group.nodes() {
        let mut outbound_full_relay_peers_count = 0;
        let mut outbound_block_relay_peers_count = 0;
        while outbound_full_relay_peers_count
            < *node_group.p2p_config().connection_count_limits.outbound_full_relay_count
            || outbound_block_relay_peers_count
                < *node_group.p2p_config().connection_count_limits.outbound_block_relay_count
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let peers_info = node.get_peers_info().await;
            outbound_full_relay_peers_count =
                peers_info.count_peers_by_role(PeerRole::OutboundFullRelay);
            outbound_block_relay_peers_count =
                peers_info.count_peers_by_role(PeerRole::OutboundBlockRelay);

            node_group.time_getter().advance_time(PEER_MGR_HEARTBEAT_INTERVAL_MAX);
        }
    }

    node_group.assert_outbound_conn_count_maximums_reached().await;
}

async fn wait_for_connections_to_impl(
    nodes: &[TestNode<Transport>],
    time_getter: &P2pBasicTestTimeGetter,
    address: SocketAddress,
    min_connected_nodes_count: usize,
) {
    let mut connected_nodes_count = 0;
    loop {
        for node in nodes {
            let peers_info = node.get_peers_info().await;
            if peers_info.info.contains_key(&address) {
                connected_nodes_count += 1;
            }
        }

        if connected_nodes_count >= min_connected_nodes_count {
            break;
        }

        time_getter.advance_time(PEER_MGR_HEARTBEAT_INTERVAL_MAX);
    }
}

async fn node_group_wait_for_connections_to(
    node_group: &TestNodeGroup<Transport>,
    address: SocketAddress,
    min_connected_nodes_count: usize,
) {
    wait_for_connections_to_impl(
        node_group.nodes(),
        node_group.time_getter(),
        address,
        min_connected_nodes_count,
    )
    .await
}

async fn node_wait_for_connection_to(
    node: &TestNode<Transport>,
    time_getter: &P2pBasicTestTimeGetter,
    address: SocketAddress,
) {
    wait_for_connections_to_impl(std::slice::from_ref(node), time_getter, address, 1).await
}
