// Copyright (c) 2023 RBB S.r.l
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

use std::time::Duration;

use utils::{bloom_filters::rolling_bloom_filter::RollingBloomFilter, set_flag::SetFlag};

use crate::{
    net::types::{self, Role},
    utils::rate_limiter::RateLimiter,
};

#[derive(Debug)]
pub struct SentPing {
    pub nonce: u64,
    pub timestamp: Duration,
}

pub struct PeerContext<A> {
    /// Peer information
    pub info: types::PeerInfo,

    /// Peer's address
    pub address: A,

    /// Peer's role (inbound or outbound)
    pub role: Role,

    /// Peer score
    pub score: u32,

    /// Sent ping details
    pub sent_ping: Option<SentPing>,

    /// Last ping time
    pub ping_last: Option<Duration>,

    /// Min ping time
    pub ping_min: Option<Duration>,

    /// Set if address list request was already received from this peer
    pub addr_list_req_received: SetFlag,

    /// Set if address list response was already received from this peer
    pub addr_list_resp_received: SetFlag,

    /// All addresses that were announced to or from this peer.
    /// Used to prevent infinity loops while broadcasting addresses.
    pub announced_addresses: RollingBloomFilter<A>,

    pub address_rate_limiter: RateLimiter,
}
