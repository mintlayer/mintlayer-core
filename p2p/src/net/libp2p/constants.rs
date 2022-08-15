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

//! Libp2p constants
//!
//! See protocol specification for more details

use std::time::Duration;

/// Gossipsub configuration
// TODO: config or spec?
pub const GOSSIPSUB_HEARTBEAT: Duration = Duration::from_secs(10);
pub const GOSSIPSUB_MAX_TRANSMIT_SIZE: usize = 2 * 1024 * 1024;

/// Ping configuration
/// NOTE: these are not from config but part of Mintlayer's protocol spec
pub const PING_TIMEOUT: Duration = Duration::from_secs(60);
pub const PING_INTERVAL: Duration = Duration::from_secs(60);
pub const PING_MAX_RETRIES: u32 = 3;

/// Request-response configuration
pub const REQ_RESP_TIMEOUT: Duration = Duration::from_secs(10);
pub const MESSAGE_MAX_SIZE: usize = 10 * 1024 * 1024;
// TODO: think about channel sizes
pub const CHANNEL_SIZE: usize = 64;
