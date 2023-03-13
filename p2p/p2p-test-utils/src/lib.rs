// Copyright (c) 2021-2022 RBB S.r.l
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

use std::sync::Arc;

use chainstate::{
    chainstate_interface::ChainstateInterface, make_chainstate, ChainstateConfig,
    DefaultTransactionVerificationStrategy,
};
use chainstate_test_framework::TestFramework;
use common::{
    chain::{config::ChainConfig, Block},
    primitives::Idable,
};
use mempool::{MempoolHandle, MempoolSubsystemInterface};

pub async fn start_subsystems(
    chain_config: Arc<ChainConfig>,
) -> (
    subsystem::Handle<Box<dyn ChainstateInterface>>,
    MempoolHandle,
) {
    let chainstate = make_chainstate(
        Arc::clone(&chain_config),
        ChainstateConfig::new(),
        chainstate_storage::inmemory::Store::new_empty().unwrap(),
        DefaultTransactionVerificationStrategy::new(),
        None,
        Default::default(),
    )
    .unwrap();
    start_subsystems_with_chainstate(chainstate).await
}

pub async fn start_subsystems_with_chainstate(
    chainstate: Box<dyn ChainstateInterface>,
) -> (
    subsystem::Handle<Box<dyn ChainstateInterface>>,
    MempoolHandle,
) {
    let mut manager = subsystem::Manager::new("p2p-test-manager");

    let chainstate = manager.add_subsystem("p2p-test-chainstate", chainstate);

    let mempool = mempool::make_mempool(
        chainstate.call(|c| Arc::clone(c.get_chain_config())).await.unwrap(),
        chainstate.clone(),
        Default::default(),
        mempool::SystemUsageEstimator {},
    );
    let mempool = manager
        .add_subsystem_with_custom_eventloop("p2p-test-mempool", move |call, shutdn| {
            mempool.run(call, shutdn)
        });

    tokio::spawn(async move { manager.main().await });

    (chainstate, mempool)
}

pub fn create_n_blocks(tf: &mut TestFramework, n: usize) -> Vec<Block> {
    assert!(n > 0);

    let mut blocks = Vec::with_capacity(n);

    blocks.push(tf.make_block_builder().build());
    for _ in 1..n {
        let prev_id = blocks.last().unwrap().get_id();
        blocks.push(tf.make_block_builder().with_parent(prev_id.into()).build());
    }

    blocks
}
