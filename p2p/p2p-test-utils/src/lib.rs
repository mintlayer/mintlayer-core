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

use std::{future::Future, sync::Arc, time::Duration};

use chainstate::{
    make_chainstate, ChainstateConfig, ChainstateHandle, ChainstateSubsystem,
    DefaultTransactionVerificationStrategy,
};
use chainstate_test_framework::TestFramework;
use common::{
    chain::{config::ChainConfig, Block},
    primitives::Idable,
    time_getter::TimeGetter,
};
use logging::log;
use mempool::{MempoolConfig, MempoolHandle};
use subsystem::{ManagerJoinHandle, ShutdownTrigger};
use test_utils::mock_time_getter::mocked_time_getter_milliseconds;
use utils::atomics::SeqCstAtomicU64;

use crate::panic_handling::get_panic_notification;

mod panic_handling;

pub fn start_subsystems(
    chain_config: Arc<ChainConfig>,
) -> (
    ChainstateHandle,
    MempoolHandle,
    ShutdownTrigger,
    ManagerJoinHandle,
) {
    let time_getter: TimeGetter = Default::default();
    let chainstate = make_chainstate(
        Arc::clone(&chain_config),
        ChainstateConfig::new(),
        chainstate_storage::inmemory::Store::new_empty().unwrap(),
        DefaultTransactionVerificationStrategy::new(),
        None,
        time_getter.clone(),
    )
    .unwrap();
    let mempool_config = Arc::new(MempoolConfig::new());
    start_subsystems_generic(
        chainstate,
        chain_config,
        mempool_config,
        time_getter,
        tracing::Span::current(),
    )
}

pub fn start_subsystems_generic(
    chainstate: ChainstateSubsystem,
    chain_config: Arc<ChainConfig>,
    mempool_config: Arc<MempoolConfig>,
    time_getter: TimeGetter,
    tracing_span: tracing::Span,
) -> (
    ChainstateHandle,
    MempoolHandle,
    ShutdownTrigger,
    ManagerJoinHandle,
) {
    let mut manager = subsystem::Manager::new("p2p-test-manager");
    let shutdown_trigger = manager.make_shutdown_trigger();

    let chainstate = manager.add_subsystem("p2p-test-chainstate", chainstate);

    let mempool = mempool::make_mempool(
        chain_config,
        mempool_config,
        chainstate.clone(),
        time_getter,
    );
    let mempool = manager.add_custom_subsystem("p2p-test-mempool", |handle| mempool.init(handle));

    let manager_handle = manager.main_in_task_in_span(tracing_span);

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

#[derive(Clone)]
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

    pub fn is_same_instance(&self, other: &P2pBasicTestTimeGetter) -> bool {
        Arc::ptr_eq(&self.current_time_millis, &other.current_time_millis)
    }
}

/// A timeout for blocking calls.
pub const LONG_TIMEOUT: Duration = Duration::from_secs(600);
/// A short timeout for events that shouldn't occur.
pub const SHORT_TIMEOUT: Duration = Duration::from_millis(500);

/// This function can be called on the entire async test's future to ensure that it completes
/// in a reasonable time.
///
/// It can also ensure that the future will complete early once a panic occurs anywhere; this
/// may be important when debugging sporadically failing tests that can only be debugged by
/// examining the logs (and running a test for LONG_TIMEOUT time may produce an enormous amount
/// of logs). Unfortunately, this mechanism will not work properly if multiple tests are failing
/// simultaneously or if there is a "should_panic" test. So, we only enable it if running under
/// 'nextest' (which runs each test in a separate process) or if forced via a custom env var.
pub async fn run_with_timeout<F>(future: F)
where
    F: Future,
{
    // Note: "NEXTEST" is always defined by nextest when running the tests, see
    // https://nexte.st/book/env-vars.html#environment-variables-nextest-sets
    let running_under_nextest = std::env::var("NEXTEST").is_ok();
    let custom_env_var_set = std::env::var("ML_P2P_TEST_ENABLE_EARLY_PANIC_DETECTION").is_ok();
    let can_stop_on_panic = running_under_nextest || custom_env_var_set;

    let future_or_panic = async {
        tokio::select! {
            () = get_panic_notification(), if can_stop_on_panic => {
                // Note that this line may not be printed to the log after all.
                // The reason is that (it looks like) tokio::select cancels (drops) the other
                // future first, before entering the handler for the completed one. And dropping
                // the test's future may panic itself, e.g. because the subsystem manager's handle
                // hasn't been joined.
                log::debug!("Stopping current test because a panic has been detected");
            },
            _ = future => {
            },
        }
    };

    tokio::time::timeout(LONG_TIMEOUT, future_or_panic).await.unwrap();
}

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
    ($receiver:expr) => {
        $crate::expect_future_val!($receiver.recv()).unwrap()
    };
}

/// Try receiving a message from the tokio channel; expect that a timeout is reached.
#[macro_export]
macro_rules! expect_no_recv {
    ($receiver:expr) => {
        $crate::expect_no_future_val!($receiver.recv())
    };
}
