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
use common::chain::ChainConfig;
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
    };

    let rpc_subsys = rpc::Builder::new(rpc_config)
        .register(chainstate_subsys.clone().into_rpc())
        .build()
        .await
        .unwrap();

    let rpc_bind_address = rpc_subsys.http_address().cloned().unwrap();

    let _rpc = manager.add_subsystem("rpc-test", rpc_subsys);

    tokio::spawn(async move { manager.main().await });

    (shutdown_trigger, chainstate_subsys, rpc_bind_address)
}

// TODO: why do we need multi_thread? Otherwise, rpc calls block forever.
#[tokio::test(flavor = "multi_thread")]
async fn wallet_basic_rpc_communication() {
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());

    let (_shutdown_trigger, _chainstate_handle, rpc_bind_address) =
        start_subsystems(chain_config, "127.0.0.1:0".to_string()).await;

    std::thread::sleep(std::time::Duration::from_secs(2));

    let rpc_client = make_rpc_client(rpc_bind_address.to_string()).unwrap();

    let _best_block_id = rpc_client.get_best_block_id().unwrap();
}
