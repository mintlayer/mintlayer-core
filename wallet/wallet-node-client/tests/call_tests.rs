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

use chainstate::{
    chainstate_interface::ChainstateInterface, make_chainstate, rpc::ChainstateRpcServer,
    ChainstateConfig, DefaultTransactionVerificationStrategy,
};
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, BlockReward, ConsensusData},
        Block, ChainConfig,
    },
    primitives::{Idable, H256},
};
use node_comm::{make_rpc_client, node_traits::NodeInterface};
use rpc::RpcConfig;
use subsystem::manager::ShutdownTrigger;

pub async fn start_subsystems(
    chain_config: Arc<ChainConfig>,
    rpc_bind_address: String,
) -> (
    ShutdownTrigger,
    subsystem::Handle<Box<dyn ChainstateInterface>>,
    SocketAddr,
) {
    let mut manager = subsystem::Manager::new("test-manager");
    let shutdown_trigger = manager.make_shutdown_trigger();

    let chainstate = make_chainstate(
        Arc::clone(&chain_config),
        ChainstateConfig::new(),
        chainstate_storage::inmemory::Store::new_empty().unwrap(),
        DefaultTransactionVerificationStrategy::new(),
        None,
        Default::default(),
    )
    .unwrap();

    let chainstate_subsys = manager.add_subsystem("test-chainstate", chainstate);

    let rpc_config = RpcConfig {
        http_bind_address: SocketAddr::from_str(&rpc_bind_address)
            .expect("Address must be correct")
            .into(),
        http_enabled: true.into(),
        ws_bind_address: SocketAddr::from_str("127.0.0.1:3030")
            .expect("Address must be correct")
            .into(),
        ws_enabled: false.into(),
        username: None,
        password: None,
        cookie_file: None,
    };

    let rpc_subsys = rpc::Builder::new(rpc_config, None)
        .unwrap()
        .register(chainstate_subsys.clone().into_rpc())
        .build()
        .await
        .unwrap();

    let rpc_bind_address = rpc_subsys.http_address().cloned().unwrap();

    let _rpc = manager.add_subsystem("rpc-test", rpc_subsys);

    tokio::spawn(async move { manager.main().await });

    (shutdown_trigger, chainstate_subsys, rpc_bind_address)
}

#[tokio::test]
async fn wallet_rpc_communication() {
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());

    let (_shutdown_trigger, chainstate_handle, rpc_bind_address) =
        start_subsystems(chain_config.clone(), "127.0.0.1:0".to_string()).await;

    let rpc_client = make_rpc_client(rpc_bind_address.to_string()).await.unwrap();

    let best_height = rpc_client.get_best_block_height().await.unwrap();

    assert_eq!(best_height.into_int(), 0);

    let best_block_id = rpc_client.get_best_block_id().await.unwrap();

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

    let best_height = rpc_client.get_best_block_height().await.unwrap();

    assert_eq!(best_height.into_int(), 1);

    let best_block_id = rpc_client.get_best_block_id().await.unwrap();

    assert_eq!(best_block_id, block_1_id);
    assert_eq!(&best_block_id, block_index_1.block_id());

    assert_eq!(
        rpc_client.get_block_id_at_height(0.into()).await.unwrap().unwrap(),
        chain_config.genesis_block_id()
    );

    assert_eq!(
        rpc_client.get_block_id_at_height(1.into()).await.unwrap().unwrap(),
        block_1_id
    );

    assert_eq!(
        rpc_client.get_block_id_at_height(2.into()).await.unwrap(),
        None
    );

    let block_1 = rpc_client.get_block(best_block_id.get().into()).await.unwrap().unwrap();

    assert_eq!(block_1.get_id(), block_1_id);

    let block_2 = rpc_client.get_block(H256::zero().into()).await.unwrap();

    assert_eq!(block_2, None);
}
