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

use std::{sync::Arc, time::Duration};

use tempfile::TempDir;

use chainstate::{make_chainstate, ChainstateConfig, DefaultTransactionVerificationStrategy};
use common::chain::config::create_mainnet;
use logging::log;
use mempool::MempoolSubsystemInterface;

use p2p::{
    interface::p2p_interface::P2pSubsystemInterface, make_p2p,
    peer_manager::peerdb::storage_impl::PeerDbStorageImpl, testing_utils::test_p2p_config,
};

// Check that the p2p shutdown isn't timed out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_timeout() {
    // TODO: FIXME: Remove.
    logging::init_logging(Some(""));

    let chain_config = Arc::new(create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());

    let timeout = Duration::from_secs(3);
    let mut manager = subsystem::Manager::new_with_config(subsystem::manager::ManagerConfig {
        name: "shutdown-test",
        shutdown_timeout_per_subsystem: Some(timeout.clone()),
    });
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
    let chainstate = manager.add_subsystem("shutdown-test-chainstate", chainstate);

    let mempool = mempool::make_mempool(
        Arc::clone(&chain_config),
        chainstate.clone(),
        Default::default(),
        mempool::SystemUsageEstimator {},
    );
    let mempool = manager.add_subsystem_with_custom_eventloop("shutdown-test-mempool", {
        move |call, shutdown| mempool.run(call, shutdown)
    });

    let lmdb_dir = TempDir::new().unwrap();
    let peerdb_storage = PeerDbStorageImpl::new(storage_lmdb::Lmdb::new(
        lmdb_dir.as_ref().to_owned(),
        Default::default(),
        Default::default(),
        Default::default(),
    ))
    .unwrap();
    let p2p = make_p2p(
        Arc::clone(&chain_config),
        p2p_config,
        chainstate.clone(),
        mempool.clone(),
        Default::default(),
        peerdb_storage,
    )
    .unwrap();
    let _p2p = manager.add_subsystem_with_custom_eventloop("shutdown-test-p2p", {
        move |call, shutdown| p2p.run(call, shutdown)
    });

    let task = manager.main_in_task();
    // TODO: FIXME: Remove:
    tokio::time::sleep(Duration::from_secs(1)).await;
    log::info!("FIXME: INITIATE SHUTDOWN");
    shutdown_trigger.initiate();
    tokio::time::timeout(timeout, task.join()).await.unwrap();
    log::info!("FIXME: EVERYTHING IS SHUT DOWN");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_order() {
    // TODO: FIXME: Use mocks to test the shutdown order.
}
