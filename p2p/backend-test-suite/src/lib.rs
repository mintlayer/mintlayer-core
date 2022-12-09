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
mod sync;

use std::fmt::Debug;

use libtest_mimic::{Arguments, Trial};

use p2p::net::{ConnectivityService, NetworkingService, SyncingMessagingService};
use p2p::testing_utils::TestTransportMaker;

/// Runs all tests.
pub fn run<A, S>()
where
    A: TestTransportMaker<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService + Debug + 'static,
    S::ConnectivityHandle: ConnectivityService<S> + Debug,
    S::SyncingMessagingHandle: SyncingMessagingService<S> + Debug,
{
    logging::init_logging::<&str>(None);
    let args = Arguments::from_args();
    libtest_mimic::run(&args, tests::<A, S>()).exit();
}

/// Collects all backend agnostic tests.
fn tests<A, S>() -> Vec<Trial>
where
    A: TestTransportMaker<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService + Debug + 'static,
    S::ConnectivityHandle: ConnectivityService<S> + Debug,
    S::SyncingMessagingHandle: SyncingMessagingService<S> + Debug,
{
    std::iter::empty()
        .chain(connect::tests::<A, S>())
        .chain(block_announcement::tests::<A, S>())
        .chain(sync::tests::<A, S>())
        .chain(ban::tests::<A, S>())
        .collect()
}
