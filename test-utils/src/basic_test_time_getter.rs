// Copyright (c) 2021-2024 RBB S.r.l
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

#![allow(clippy::unwrap_used)]

use std::{sync::Arc, time::Duration};

use common::time_getter::TimeGetter;
use utils::atomics::SeqCstAtomicU64;

use crate::mock_time_getter::mocked_time_getter_milliseconds;

#[derive(Clone)]
pub struct BasicTestTimeGetter {
    current_time_millis: Arc<SeqCstAtomicU64>,
}

impl BasicTestTimeGetter {
    pub fn new() -> Self {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap();
        let current_time_millis = Arc::new(SeqCstAtomicU64::new(current_time.as_millis() as u64));
        Self {
            current_time_millis,
        }
    }

    pub fn get_time_getter(&self) -> TimeGetter {
        mocked_time_getter_milliseconds(Arc::clone(&self.current_time_millis))
    }

    pub fn advance_time(&self, duration: Duration) {
        self.current_time_millis.fetch_add(duration.as_millis() as u64);
    }

    pub fn is_same_instance(&self, other: &BasicTestTimeGetter) -> bool {
        Arc::ptr_eq(&self.current_time_millis, &other.current_time_millis)
    }
}
