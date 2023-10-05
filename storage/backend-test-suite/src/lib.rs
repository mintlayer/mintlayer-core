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

//! Test suite for storage backends

#![allow(clippy::unwrap_used)]

// Support modules
#[macro_use]
pub mod prelude;
pub mod model;

// Test modules
mod basic;
mod concurrent;

#[cfg(not(loom))]
mod property;
#[cfg(loom)]
mod property {
    // No property tests with loom for now
    pub fn tests<F>(_backend_fn: F) -> impl Iterator<Item = libtest_mimic::Trial> {
        std::iter::empty()
    }
}

use prelude::*;

/// Get all tests
fn tests<B: 'static + Backend, F: BackendFn<B>>(backend_fn: F) -> Vec<libtest_mimic::Trial> {
    let backend_fn = Arc::new(backend_fn);
    std::iter::empty()
        .chain(basic::tests(Arc::clone(&backend_fn)))
        .chain(concurrent::tests(Arc::clone(&backend_fn)))
        .chain(property::tests(backend_fn))
        .collect()
}

/// Main test suite entry point
#[must_use = "Test outcome ignored, add a call to .exit()"]
pub fn main<B: 'static + Backend, F: BackendFn<B>>(backend_fn: F) -> libtest_mimic::Conclusion {
    logging::init_logging();
    let args = libtest_mimic::Arguments::from_args();
    libtest_mimic::run(&args, tests(backend_fn))
}
