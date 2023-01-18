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
mod peer_manager_peerdb;
mod sync;

use std::fmt::Debug;

use libtest_mimic::{Arguments, Trial};

use p2p::{
    net::{
        default_backend::types::PeerId, ConnectivityService, NetworkingService,
        SyncingMessagingService,
    },
    testing_utils::{RandomAddressMaker, TestTransportMaker},
};

/// Runs all tests.
pub fn run<T, S, A>()
where
    T: TestTransportMaker<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService<PeerId = PeerId> + Debug + 'static,
    S::ConnectivityHandle: ConnectivityService<S> + Debug,
    S::SyncingMessagingHandle: SyncingMessagingService<S> + Debug,
    A: RandomAddressMaker<Address = S::Address>,
{
    logging::init_logging::<&str>(None);
    let args = Arguments::from_args();
    libtest_mimic::run(&args, tests::<T, S, A>()).exit();
}

/// Collects all backend agnostic tests.
fn tests<T, S, A>() -> Vec<Trial>
where
    T: TestTransportMaker<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService<PeerId = PeerId> + Debug + 'static,
    S::ConnectivityHandle: ConnectivityService<S> + Debug,
    S::SyncingMessagingHandle: SyncingMessagingService<S> + Debug,
    A: RandomAddressMaker<Address = S::Address>,
{
    std::iter::empty()
        .chain(connect::tests::<T, S, A>())
        .chain(block_announcement::tests::<T, S, A>())
        .chain(sync::tests::<T, S, A>())
        .chain(ban::tests::<T, S, A>())
        .chain(peer_manager_peerdb::tests::<T, S, A>())
        .collect()
}
