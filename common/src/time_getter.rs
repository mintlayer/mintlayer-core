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

use std::sync::Arc;

use crate::primitives::time::{self, Time};

pub trait TimeGetterFn: Send + Sync {
    fn get_time(&self) -> Time;
}

/// A time getter representing the wall clock.
#[derive(Clone)]
pub struct TimeGetter {
    f: Arc<dyn TimeGetterFn>,
}

impl utils::shallow_clone::ShallowClone for TimeGetter {
    fn shallow_clone(&self) -> Self {
        Self::clone(self)
    }
}

impl TimeGetter {
    pub fn new(f: Arc<dyn TimeGetterFn>) -> Self {
        Self { f }
    }

    pub fn get_time(&self) -> Time {
        self.f.get_time()
    }

    pub fn getter(&self) -> &dyn TimeGetterFn {
        &*self.f
    }
}

impl Default for TimeGetter {
    fn default() -> Self {
        Self::new(Arc::new(DefaultTimeGetterFn::new()))
    }
}

struct DefaultTimeGetterFn;

impl DefaultTimeGetterFn {
    fn new() -> Self {
        Self
    }
}

impl TimeGetterFn for DefaultTimeGetterFn {
    fn get_time(&self) -> Time {
        time::get_time()
    }
}

pub trait MonotonicTimeGetterFn: Send + Sync {
    fn get_time(&self) -> std::time::Instant;
}

/// A time getter representing a monotonically non-decreasing clock.
///
/// Note that mocking this one only makes sense in places where different `Instant` values are
/// compared explicitly, instead of e.g. relying on tokio's `sleep_until` or `interval_at`. In
/// the latter case, `tokio::time::advance` and `pause` can be used. But note that they require
/// the `current_thread` runtime, which is not always possible (e.g. subsystems' `BlockingHandle`
/// needs a multithreaded one), and this is the reason why we have this `MonotonicTimeGetter`.
#[derive(Clone)]
pub struct MonotonicTimeGetter {
    f: Arc<dyn MonotonicTimeGetterFn>,
}

impl utils::shallow_clone::ShallowClone for MonotonicTimeGetter {
    fn shallow_clone(&self) -> Self {
        Self::clone(self)
    }
}

impl MonotonicTimeGetter {
    pub fn new(f: Arc<dyn MonotonicTimeGetterFn>) -> Self {
        Self { f }
    }

    pub fn get_time(&self) -> std::time::Instant {
        self.f.get_time()
    }

    pub fn getter(&self) -> &dyn MonotonicTimeGetterFn {
        &*self.f
    }
}

impl Default for MonotonicTimeGetter {
    fn default() -> Self {
        Self::new(Arc::new(DefaultMonotonicTimeGetterFn::new()))
    }
}

struct DefaultMonotonicTimeGetterFn;

impl DefaultMonotonicTimeGetterFn {
    fn new() -> Self {
        Self
    }
}

impl MonotonicTimeGetterFn for DefaultMonotonicTimeGetterFn {
    fn get_time(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
}
