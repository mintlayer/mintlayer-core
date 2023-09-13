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
pub struct PeerActivity {
    expecting_headers_since: Option<Duration>,
    expecting_blocks_since: Option<Duration>,
}

impl PeerActivity {
    pub fn new() -> PeerActivity {
        PeerActivity {
            expecting_headers_since: None,
            expecting_blocks_since: None,
        }
    }

    pub fn expecting_headers_since(&mut self) -> Option<Duration> {
        self.expecting_headers_since
    }

    pub fn expecting_blocks_since(&mut self) -> Option<Duration> {
        self.expecting_blocks_since
    }

    pub fn set_expecting_headers_since(&mut self, time: Option<Duration>) {
        self.expecting_headers_since = time;
    }

    pub fn set_expecting_blocks_since(&mut self, time: Option<Duration>) {
        self.expecting_blocks_since = time;
    }

    pub fn earliest_expected_activity_time(&self) -> Option<Duration> {
        match (self.expecting_headers_since, self.expecting_blocks_since) {
            (None, None) => None,
            (Some(time), None) | (None, Some(time)) => Some(time),
            (Some(time1), Some(time2)) => Some(std::cmp::min(time1, time2)),
        }
    }
}
