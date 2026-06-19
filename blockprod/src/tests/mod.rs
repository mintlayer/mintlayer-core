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

pub mod helpers;

use std::sync::Arc;

use crate::{
    make_blockproduction, test_blockprod_config, tests::helpers::BlockprodTestSetupBuilder,
};

#[ctor::ctor]
fn init() {
    logging::init_logging();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_make_blockproduction() {
    let (blockprod_setup, mut manager) = BlockprodTestSetupBuilder::new().build();

    let blockprod = make_blockproduction(
        Arc::clone(&blockprod_setup.chain_config),
        Arc::new(test_blockprod_config()),
        blockprod_setup.chainstate.clone(),
        blockprod_setup.mempool.clone(),
        blockprod_setup.p2p.clone(),
        blockprod_setup.time_getter,
    )
    .unwrap();

    let blockprod = manager.add_direct_subsystem("blockprod", blockprod);
    let shutdown = manager.make_shutdown_trigger();

    tokio::spawn(async move {
        blockprod
            .call_async_mut(move |this| {
                Box::pin(async move {
                    let stopped_jobs_count = this.stop_all().await;

                    assert_eq!(
                        stopped_jobs_count,
                        Ok(0),
                        "Failed to stop non-existent jobs"
                    );
                    shutdown.initiate();
                })
            })
            .await
            .unwrap();
    });

    manager.main().await;
}
