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

//! A test suite for p2p backends.

#![allow(clippy::unwrap_used)]

#[macro_use]
mod utils;
mod ban;
mod block_announcement;
mod connect;
mod events;

use std::fmt::Debug;

use libtest_mimic::{Arguments, Trial};

use networking::test_helpers::TestTransportMaker;
use p2p::net::{ConnectivityService, MessagingService, NetworkingService, SyncingEventReceiver};

// TODO: these tests may benefit from randomness (see https://github.com/mintlayer/mintlayer-core/issues/656#issuecomment-1474408003).
// Note: the easiest way of introducing randomness here is using `with_rng_seed` (which is currently lives
// in `storage-backend-test-suite` and will have to be moved to test-utils), instead of trying to fit `rstest` here.

/// Runs all tests.
pub fn run<T, N>()
where
    T: TestTransportMaker<Transport = N::Transport>,
    N: NetworkingService + Debug + 'static,
    N::ConnectivityHandle: ConnectivityService<N> + Debug,
    N::MessagingHandle: MessagingService + Debug,
    N::SyncingEventReceiver: SyncingEventReceiver + Debug,
{
    rlimit::increase_nofile_limit(10 * 1024).unwrap();
    logging::init_logging();
    let args = Arguments::from_args();
    libtest_mimic::run(&args, tests::<T, N>()).exit();
}

/// Collects all backend agnostic tests.
fn tests<T, N>() -> Vec<Trial>
where
    T: TestTransportMaker<Transport = N::Transport>,
    N: NetworkingService + Debug + 'static,
    N::ConnectivityHandle: ConnectivityService<N> + Debug,
    N::MessagingHandle: MessagingService + Debug,
    N::SyncingEventReceiver: SyncingEventReceiver + Debug,
{
    std::iter::empty()
        .chain(connect::tests::<T, N>())
        .chain(block_announcement::tests::<T, N>())
        .chain(ban::tests::<T, N>())
        .chain(events::tests::<T, N>())
        .collect()
}
