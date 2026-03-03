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

use common::primitives::time::Time;
use p2p_types::socket_address::SocketAddress;
use utils::{bloom_filters::rolling_bloom_filter::RollingBloomFilter, set_flag::SetFlag};

use crate::{
    net::types::{PeerInfo, PeerRole},
    sync::sync_status::PeerBlockSyncStatus,
    utils::rate_limiter::RateLimiter,
};

#[derive(Debug)]
pub struct SentPing {
    pub nonce: u64,
    pub timestamp: Time,
}

pub struct PeerContext {
    pub created_at: Time,

    /// Peer information
    pub info: PeerInfo,

    /// Peer's address
    pub peer_address: SocketAddress,

    /// Bind address of this node's side of the connection.
    pub bind_address: SocketAddress,

    pub peer_role: PeerRole,

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
    pub announced_addresses: RollingBloomFilter<SocketAddress>,

    pub address_rate_limiter: RateLimiter,

    /// Expected listening address of this node (publicly routable IP + local listening port).
    /// Can be set for outbound connections only.
    pub discovered_own_address: Option<SocketAddress>,

    /// Last time the peer has sent us a block that became our tip.
    pub last_tip_block_time: Option<Time>,

    pub last_tx_time: Option<Time>,

    /// Certain information from the block sync manager that the peer manager may be interested in.
    pub block_sync_status: PeerBlockSyncStatus,
}
