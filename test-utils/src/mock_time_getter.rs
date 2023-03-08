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

use common::time_getter::{TimeGetter, TimeGetterFn};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

pub fn mocked_time_getter_seconds(seconds: Arc<AtomicU64>) -> TimeGetter {
    TimeGetter::new(Arc::new(MockedMsecTimeGetterFn::new(seconds, 1000)))
}

pub fn mocked_time_getter_milliseconds(milliseconds: Arc<AtomicU64>) -> TimeGetter {
    TimeGetter::new(Arc::new(MockedMsecTimeGetterFn::new(milliseconds, 1)))
}

struct MockedMsecTimeGetterFn {
    count: Arc<AtomicU64>,
    multiplier: u64,
}

impl MockedMsecTimeGetterFn {
    fn new(count: Arc<AtomicU64>, multiplier: u64) -> Self {
        Self { count, multiplier }
    }
}

impl TimeGetterFn for MockedMsecTimeGetterFn {
    fn get_time(&self) -> Duration {
        Duration::from_millis(self.multiplier * self.count.load(Ordering::SeqCst))
    }
}

#[cfg(test)]
mod test {
    use std::sync::atomic::Ordering;

    use crate::mock_time_getter::mocked_time_getter_seconds;

    use super::*;

    #[test]
    fn test_mocked_time_getter_seconds() {
        let seconds = Arc::new(AtomicU64::new(12345));
        let time_getter = mocked_time_getter_seconds(Arc::clone(&seconds));
        let time = time_getter.get_time();
        seconds.fetch_add(123, Ordering::SeqCst);
        assert_eq!(time_getter.get_time() - time, Duration::from_secs(123));
    }

    #[test]
    fn test_mocked_time_getter_milliseconds() {
        let milliseconds = Arc::new(AtomicU64::new(12345));
        let time_getter = mocked_time_getter_milliseconds(Arc::clone(&milliseconds));
        let time = time_getter.get_time();
        milliseconds.fetch_add(123, Ordering::SeqCst);
        assert_eq!(time_getter.get_time() - time, Duration::from_millis(123));
    }
}
