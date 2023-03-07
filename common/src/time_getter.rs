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

use std::{sync::Arc, time::Duration};

use crate::primitives::time;

pub trait TimeGetterFn: Send + Sync {
    fn get_time(&self) -> Duration;
}

/// A function wrapper that contains the function that will be used to get the current time in chainstate
#[derive(Clone)]
pub struct TimeGetter {
    f: Arc<dyn TimeGetterFn>,
}

impl TimeGetter {
    pub fn new(f: Arc<dyn TimeGetterFn>) -> Self {
        Self { f }
    }

    pub fn get_time(&self) -> Duration {
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
    fn get_time(&self) -> Duration {
        time::get_time()
    }
}
