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

use std::time::Duration;

use serde::{Deserialize, Serialize};

use serialization::{Decode, Encode};

use crate::primitives::time::Time;

pub type BlockTimestampInternalType = u64;

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Encode, Decode, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct BlockTimestamp {
    #[codec(compact)]
    timestamp: BlockTimestampInternalType,
}

impl std::fmt::Display for BlockTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.timestamp.fmt(f)
    }
}

impl BlockTimestamp {
    pub const fn from_int_seconds(timestamp: BlockTimestampInternalType) -> Self {
        Self { timestamp }
    }

    pub const fn from_duration_since_epoch(duration: Duration) -> Self {
        Self {
            timestamp: duration.as_secs(),
        }
    }

    pub const fn as_duration_since_epoch(&self) -> Duration {
        Duration::from_secs(self.timestamp)
    }

    pub const fn as_int_seconds(&self) -> BlockTimestampInternalType {
        self.timestamp
    }

    pub const fn from_time(time: Time) -> Self {
        Self::from_duration_since_epoch(time.as_duration_since_epoch())
    }

    pub const fn into_time(self) -> Time {
        Time::from_duration_since_epoch(self.as_duration_since_epoch())
    }

    pub fn add_int_seconds(&self, seconds: BlockTimestampInternalType) -> Option<BlockTimestamp> {
        self.timestamp.checked_add(seconds).map(|ts| Self { timestamp: ts })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_iteration() {
        let timestamp = BlockTimestamp::from_int_seconds(u64::MAX);
        let timestamp_next = timestamp.add_int_seconds(1);
        assert!(timestamp_next.is_none());
    }
}
