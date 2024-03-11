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

use chainstate::{make_chainstate, ChainstateConfig, DefaultTransactionVerificationStrategy};
use common::chain::config::create_unit_test_config;
use mempool::MempoolConfig;
use storage_inmemory::InMemory;

use p2p::{
    make_p2p, peer_manager::peerdb::storage_impl::PeerDbStorageImpl, testing_utils::test_p2p_config,
};

#[ctor::ctor]
fn init() {
    logging::init_logging();
}

#[tracing::instrument]
// Check that the p2p shutdown isn't timed out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_timeout() {
    let chain_config = Arc::new(create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());

    let timeout = Duration::from_secs(3);
    let mut manager = subsystem::Manager::new_with_config(
        subsystem::ManagerConfig::new("shutdown-test").with_shutdown_timeout_per_subsystem(timeout),
    );
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
    let mempool_config = Arc::new(MempoolConfig::new());

    let mempool = mempool::make_mempool(
        Arc::clone(&chain_config),
        mempool_config,
        chainstate.clone(),
        Default::default(),
    );
    let mempool = manager.add_custom_subsystem("shutdown-test-mempool", |hdl| mempool.init(hdl));

    let peerdb_storage = PeerDbStorageImpl::new(InMemory::new()).unwrap();
    let _p2p = make_p2p(
        true,
        Arc::clone(&chain_config),
        p2p_config,
        chainstate.clone(),
        mempool.clone(),
        Default::default(),
        peerdb_storage,
    )
    .unwrap()
    .add_to_manager("shutdown-test-p2p", &mut manager);

    let task = manager.main_in_task();
    shutdown_trigger.initiate();
    tokio::time::timeout(timeout, task.join()).await.unwrap();
}
