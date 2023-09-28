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

use std::{sync::Arc, time::Duration};

use chainstate::{
    chainstate_interface::ChainstateInterface, make_chainstate, ChainstateConfig,
    DefaultTransactionVerificationStrategy,
};
use chainstate_test_framework::TestFramework;
use common::{
    chain::{config::ChainConfig, Block},
    primitives::Idable,
    time_getter::TimeGetter,
};
use mempool::{MempoolHandle, MempoolSubsystemInterface};
use subsystem::manager::{ManagerJoinHandle, ShutdownTrigger};
use test_utils::mock_time_getter::mocked_time_getter_milliseconds;
use utils::atomics::SeqCstAtomicU64;

pub fn start_subsystems(
    chain_config: Arc<ChainConfig>,
) -> (
    subsystem::Handle<Box<dyn ChainstateInterface>>,
    MempoolHandle,
    ShutdownTrigger,
    ManagerJoinHandle,
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
    start_subsystems_with_chainstate(chainstate, chain_config)
}

pub fn start_subsystems_with_chainstate(
    chainstate: Box<dyn ChainstateInterface>,
    chain_config: Arc<ChainConfig>,
) -> (
    subsystem::Handle<Box<dyn ChainstateInterface>>,
    MempoolHandle,
    ShutdownTrigger,
    ManagerJoinHandle,
) {
    let mut manager = subsystem::Manager::new("p2p-test-manager");
    let shutdown_trigger = manager.make_shutdown_trigger();

    let chainstate = manager.add_subsystem("p2p-test-chainstate", chainstate);

    let mempool = mempool::make_mempool(chain_config, chainstate.clone(), Default::default());
    let mempool = manager.add_subsystem_with_custom_eventloop("p2p-test-mempool", {
        move |call, shutdn| mempool.run(call, shutdn)
    });

    let manager_handle = manager.main_in_task();

    (chainstate, mempool, shutdown_trigger, manager_handle)
}

// TODO: unify block creation utilities in p2p tests (others are in p2p/src/sync/tests/helpers,
// may be in some other places too).
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

pub struct P2pBasicTestTimeGetter {
    current_time_millis: Arc<SeqCstAtomicU64>,
}

impl P2pBasicTestTimeGetter {
    pub fn new() -> Self {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap();
        let current_time_millis = Arc::new(SeqCstAtomicU64::new(current_time.as_millis() as u64));
        Self {
            current_time_millis,
        }
    }

    pub fn get_time_getter(&self) -> TimeGetter {
        mocked_time_getter_milliseconds(Arc::clone(&self.current_time_millis))
    }

    pub fn advance_time(&self, duration: Duration) {
        self.current_time_millis.fetch_add(duration.as_millis() as u64);
    }
}

/// A timeout for blocking calls.
pub const LONG_TIMEOUT: Duration = Duration::from_secs(60);
/// A short timeout for events that shouldn't occur.
pub const SHORT_TIMEOUT: Duration = Duration::from_millis(500);

/// Await for the specified future for some reasonably big amount of time; panic if the timeout
/// is reached.
// Note: this is implemented as a macro until #[track_caller] works correctly with async functions
// (needed to print the caller location if 'unwrap' fails). Same for the other macros below.
#[macro_export]
macro_rules! expect_future_val {
    ($fut:expr) => {
        tokio::time::timeout($crate::LONG_TIMEOUT, $fut)
            .await
            .expect("Failed to receive value in time")
    };
}

/// Await for the specified future for a short time, expecting a timeout.
#[macro_export]
macro_rules! expect_no_future_val {
    ($fut:expr) => {
        tokio::time::timeout($crate::SHORT_TIMEOUT, $fut).await.unwrap_err();
    };
}

/// Try receiving a message from the tokio channel; panic if the channel is closed or the timeout
/// is reached.
#[macro_export]
macro_rules! expect_recv {
    ($rx:expr) => {
        $crate::expect_future_val!($rx.recv()).unwrap()
    };
}

/// Try receiving a message from the tokio channel; expect that a timeout is reached.
#[macro_export]
macro_rules! expect_no_recv {
    ($rx:expr) => {
        $crate::expect_no_future_val!($rx.recv())
    };
}
