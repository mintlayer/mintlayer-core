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
mod frontend;

#[cfg(not(loom))]
mod property;
#[cfg(loom)]
mod property {
    // No property tests with loom for now
    pub fn tests<F>(_backend_fn: F) -> impl Iterator<Item = libtest_mimic::Trial> {
        std::iter::empty()
    }
    pub fn async_tests<F>(_backend_fn: F) -> impl Iterator<Item = libtest_mimic::Trial> {
        std::iter::empty()
    }
}

use prelude::*;
use test_utils::random::Seed;

/// Get all tests
fn tests<B: Backend + 'static, F: BackendFn<B>>(backend_fn: F) -> Vec<libtest_mimic::Trial> {
    let backend_fn = Arc::new(backend_fn);
    std::iter::empty()
        .chain(basic::tests(Arc::clone(&backend_fn)))
        .chain(concurrent::tests(Arc::clone(&backend_fn)))
        .chain(frontend::tests(Arc::clone(&backend_fn)))
        .chain(property::tests(backend_fn))
        .collect()
}

fn async_tests<B: AsyncBackend + 'static, F: BackendFn<B>>(
    backend_fn: F,
) -> Vec<libtest_mimic::Trial> {
    let backend_fn = Arc::new(backend_fn);
    std::iter::empty()
        .chain(basic::async_tests(Arc::clone(&backend_fn)))
        .chain(concurrent::async_tests(Arc::clone(&backend_fn)))
        .chain(frontend::async_tests(Arc::clone(&backend_fn)))
        .chain(property::async_tests(backend_fn))
        .collect()
}

/// Main test suite entry point
#[must_use = "Test outcome ignored, add a call to .exit()"]
pub fn main<B: Backend + 'static, F: BackendFn<B>>(backend_fn: F) -> libtest_mimic::Conclusion {
    logging::init_logging();
    let args = libtest_mimic::Arguments::from_args();
    libtest_mimic::run(&args, tests(backend_fn))
}

/// Main test suite entry point
#[must_use = "Test outcome ignored, add a call to .exit()"]
pub fn async_main<B: AsyncBackend + 'static, F: BackendFn<B>>(
    backend_fn: F,
) -> libtest_mimic::Conclusion {
    logging::init_logging();
    let args = libtest_mimic::Arguments::from_args();
    libtest_mimic::run(&args, async_tests(backend_fn))
}

/// Generate a seed and pass it to the specified function. If the function panics, print
/// the seed to the console.
pub fn with_rng_seed<TestFunc>(test_func: TestFunc)
where
    TestFunc: FnOnce(Seed),
{
    let seed = Seed::from_entropy();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        test_func(seed);
    }));

    if let Err(err) = result {
        println!("seed = {seed:?}");
        std::panic::resume_unwind(err);
    }
}
