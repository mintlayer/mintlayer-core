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

use std::{net::SocketAddr, str::FromStr, sync::Arc};

use blockprod::{test_blockprod_config, BlockProductionHandle};
use chainstate::{
    chainstate_interface::ChainstateInterface, make_chainstate, rpc::ChainstateRpcServer,
    ChainstateConfig, ChainstateHandle, DefaultTransactionVerificationStrategy,
};
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, BlockReward, ConsensusData},
        Block, ChainConfig,
    },
    primitives::{Idable, H256},
};
use mempool::{MempoolHandle, MempoolSubsystemInterface};
use node_comm::{make_handles_client, make_rpc_client, node_traits::NodeInterface};
use p2p::P2pHandle;
use rpc::{RpcAuthData, RpcConfig};
use subsystem::manager::ShutdownTrigger;
use tokio::task::JoinHandle;

pub async fn start_subsystems(
    chain_config: Arc<ChainConfig>,
    rpc_bind_address: String,
) -> (
    ShutdownTrigger,
    ChainstateHandle,
    MempoolHandle,
    BlockProductionHandle,
    P2pHandle,
    SocketAddr,
    JoinHandle<()>,
) {
    let mut manager = subsystem::Manager::new("test-manager");
    let shutdown_trigger = manager.make_shutdown_trigger();

    let p2p_config = p2p::config::P2pConfig {
        bind_addresses: vec!["127.0.0.1:0".to_owned()],
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
        user_agent: common::primitives::user_agent::mintlayer_core_user_agent(),
        max_message_size: Default::default(),
        max_peer_tx_announcements: Default::default(),
        sync_stalling_timeout: Default::default(),
    };

    let chainstate = make_chainstate(
        Arc::clone(&chain_config),
        ChainstateConfig::new(),
        chainstate_storage::inmemory::Store::new_empty().unwrap(),
        DefaultTransactionVerificationStrategy::new(),
        None,
        Default::default(),
    )
    .unwrap();

    let chainstate_handle = manager.add_subsystem("test-chainstate", chainstate);

    let mempool = mempool::make_mempool(
        Arc::clone(&chain_config),
        chainstate_handle.clone(),
        Default::default(),
    );
    let mempool_handle = manager.add_subsystem_with_custom_eventloop("test-mempool", {
        move |call, shutdn| mempool.run(call, shutdn)
    });

    let peerdb_storage = p2p::testing_utils::peerdb_inmemory_store();
    let p2p = p2p::make_p2p(
        Arc::clone(&chain_config),
        Arc::new(p2p_config),
        chainstate_handle.clone(),
        mempool_handle.clone(),
        Default::default(),
        peerdb_storage,
    )
    .unwrap();
    let p2p_handle = manager.add_subsystem_with_custom_eventloop("test-p2p", {
        move |call, shutdown| p2p.run(call, shutdown)
    });

    let block_prod_handle = manager.add_subsystem(
        "test-blockprod",
        blockprod::make_blockproduction(
            Arc::clone(&chain_config),
            Arc::new(test_blockprod_config()),
            chainstate_handle.clone(),
            mempool_handle.clone(),
            p2p_handle.clone(),
            Default::default(),
        )
        .unwrap(),
    );

    let rpc_config = RpcConfig {
        http_bind_address: SocketAddr::from_str(&rpc_bind_address)
            .expect("Address must be correct")
            .into(),
        http_enabled: true.into(),
        ws_bind_address: SocketAddr::from_str("127.0.0.1:3030")
            .expect("Address must be correct")
            .into(),
        ws_enabled: false.into(),
    };

    let rpc_subsys = rpc::Builder::new(rpc_config, None)
        .register(chainstate_handle.clone().into_rpc())
        .build()
        .await
        .unwrap();

    let rpc_bind_address = rpc_subsys.http_address().cloned().unwrap();

    let _rpc = manager.add_subsystem("rpc-test", rpc_subsys);

    let manager_task_handle = tokio::spawn(async move { manager.main().await });

    (
        shutdown_trigger,
        chainstate_handle,
        mempool_handle,
        block_prod_handle,
        p2p_handle,
        rpc_bind_address,
        manager_task_handle,
    )
}

async fn test_wallet_node_communication(
    chain_config: Arc<ChainConfig>,
    chainstate_handle: chainstate::ChainstateHandle,
    node_interface: impl NodeInterface,
) {
    let best_height = node_interface.get_best_block_height().await.unwrap();

    assert_eq!(best_height.into_int(), 0);

    let best_block_id = node_interface.get_best_block_id().await.unwrap();

    assert_eq!(best_block_id, chain_config.genesis_block_id());

    // Submit a block and check that the best block height and id are updated.

    let block = Block::new(
        vec![],
        chain_config.genesis_block_id(),
        BlockTimestamp::from_int_seconds(
            chain_config.genesis_block().timestamp().as_int_seconds() + 1,
        ),
        ConsensusData::None,
        BlockReward::new(Vec::new()),
    )
    .unwrap();

    let block_1_id = block.get_id();

    let block_index_1 = chainstate_handle
        .call_mut(|c| c.process_block(block, chainstate::BlockSource::Local).unwrap())
        .await
        .unwrap()
        .unwrap();

    let best_height = node_interface.get_best_block_height().await.unwrap();

    assert_eq!(best_height.into_int(), 1);

    let best_block_id = node_interface.get_best_block_id().await.unwrap();

    assert_eq!(best_block_id, block_1_id);
    assert_eq!(&best_block_id, block_index_1.block_id());

    assert_eq!(
        node_interface.get_block_id_at_height(0.into()).await.unwrap().unwrap(),
        chain_config.genesis_block_id()
    );

    assert_eq!(
        node_interface.get_block_id_at_height(1.into()).await.unwrap().unwrap(),
        block_1_id
    );

    assert_eq!(
        node_interface.get_block_id_at_height(2.into()).await.unwrap(),
        None
    );

    let block_1 = node_interface.get_block(best_block_id.get().into()).await.unwrap().unwrap();

    assert_eq!(block_1.get_id(), block_1_id);

    let block_2 = node_interface.get_block(H256::zero().into()).await.unwrap();

    assert_eq!(block_2, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn node_rpc_communication() {
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());

    let (
        shutdown_trigger,
        chainstate,
        _mempool,
        _block_prod,
        _p2p,
        rpc_bind_address,
        manager_task_handle,
    ) = start_subsystems(chain_config.clone(), "127.0.0.1:0".to_string()).await;

    let rpc_client =
        make_rpc_client(rpc_bind_address.to_string(), RpcAuthData::None).await.unwrap();

    test_wallet_node_communication(chain_config, chainstate, rpc_client).await;

    shutdown_trigger.initiate();
    manager_task_handle.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn node_handle_communication() {
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());

    let (
        shutdown_trigger,
        chainstate,
        mempool,
        block_prod,
        p2p,
        _rpc_bind_address,
        manager_task_handle,
    ) = start_subsystems(chain_config.clone(), "127.0.0.1:0".to_string()).await;

    let handles_client =
        make_handles_client(chainstate.clone(), mempool, block_prod, p2p).await.unwrap();

    test_wallet_node_communication(chain_config, chainstate, handles_client).await;

    shutdown_trigger.initiate();
    manager_task_handle.await.unwrap();
}
