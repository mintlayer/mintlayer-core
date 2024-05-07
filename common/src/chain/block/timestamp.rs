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
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    rpc_description::HasValueHint,
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

    pub fn iter_up_to_including(
        &self,
        other: BlockTimestamp,
    ) -> impl Iterator<Item = BlockTimestamp> {
        (self.timestamp..=other.timestamp).map(BlockTimestamp::from_int_seconds)
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

    #[test]
    fn iteration() {
        let timestamps = BlockTimestamp::from_int_seconds(1)
            .iter_up_to_including(BlockTimestamp::from_int_seconds(3))
            .collect::<Vec<_>>();
        let expected_timestamps = vec![
            BlockTimestamp::from_int_seconds(1),
            BlockTimestamp::from_int_seconds(2),
            BlockTimestamp::from_int_seconds(3),
        ];
        assert_eq!(timestamps, expected_timestamps);
    }
}
