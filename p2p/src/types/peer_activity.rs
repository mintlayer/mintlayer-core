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

/// Activity with a peer.
#[derive(Debug)]
pub enum PeerActivity {
    /// Node is pending for further actions with a peer.
    Pending,
    /// Node has sent a header list request to a peer and is expecting a header list response.
    ExpectingHeaderList {
        /// A time when the header list request was sent.
        time: Duration,
    },
    /// Node has sent a block list request to a peer and is expecting block responses.
    ExpectingBlocks {
        /// A time when either the block list request was sent or last block response was received.
        time: Duration,
    },
}
