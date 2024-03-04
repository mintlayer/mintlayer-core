// Copyright (c) 2021-2023 RBB S.r.l
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

//! A module for tests that behave like integration tests but still need access to private data
//! via methods under #[cfg(test)],

mod bad_time_diff;
mod correct_handshake;
mod disconnect_on_will_disconnect_msg;
mod incorrect_handshake;
mod misbehavior;
mod peer_discovery_on_stale_tip;
mod same_handshake_nonce;
mod unsupported_version;

pub mod helpers;

#[ctor::ctor]
fn init() {
    logging::init_logging();
}
