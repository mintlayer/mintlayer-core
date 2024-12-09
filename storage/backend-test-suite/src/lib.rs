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
    pub fn common_tests<F>(_backend_factory: F) -> impl Iterator<Item = libtest_mimic::Trial> {
        std::iter::empty()
    }
}

use prelude::*;
use test_utils::random::Seed;

/// Get all general tests for a Backend
fn common_tests<B: Backend + 'static, F: BackendFactory<B>>(
    backend_factory: Arc<F>,
) -> Vec<libtest_mimic::Trial> {
    std::iter::empty()
        .chain(basic::common_tests(Arc::clone(&backend_factory)))
        .chain(concurrent::common_tests(Arc::clone(&backend_factory)))
        .chain(frontend::common_tests(Arc::clone(&backend_factory)))
        .chain(property::common_tests(backend_factory))
        .collect()
}

/// Get all general tests for a SharedBackend
fn common_tests_for_shared_backend<B: SharedBackend + 'static, F: BackendFactory<B>>(
    backend_factory: Arc<F>,
) -> Vec<libtest_mimic::Trial> {
    std::iter::empty()
        .chain(basic::common_tests_for_shared_backend(Arc::clone(
            &backend_factory,
        )))
        .chain(concurrent::common_tests_for_shared_backend(Arc::clone(
            &backend_factory,
        )))
        .chain(frontend::common_tests_for_shared_backend(Arc::clone(
            &backend_factory,
        )))
        .chain(property::common_tests_for_shared_backend(backend_factory))
        .collect()
}

/// Get all tests specific for shared backends
fn shared_backend_tests<B: SharedBackend + 'static, F: BackendFactory<B>>(
    backend_factory: F,
) -> Vec<libtest_mimic::Trial> {
    let backend_factory = Arc::new(backend_factory);
    std::iter::empty()
        .chain(concurrent::tests(Arc::clone(&backend_factory)))
        .collect()
}

/// Main test suite entry point.
///
/// Both `backend_factory` and `shared_backend_factory` are supposed to create the same type
/// of backend, but the latter will only be used for backends that implement SharedBackend.
#[must_use = "Test outcome ignored, add a call to .exit()"]
pub fn main<B, F, SB, SF>(
    backend_factory: F,
    shared_backend_factory: Option<SF>,
) -> libtest_mimic::Conclusion
where
    B: Backend + 'static,
    F: BackendFactory<B>,
    SB: SharedBackend + 'static,
    SF: BackendFactory<SB>,
{
    logging::init_logging();
    let args = libtest_mimic::Arguments::from_args();
    let backend_factory = Arc::new(backend_factory);
    let mut tests = common_tests(backend_factory);

    if let Some(shared_backend_factory) = shared_backend_factory {
        let shared_backend_factory = Arc::new(shared_backend_factory);

        tests.extend(common_tests_for_shared_backend(Arc::clone(
            &shared_backend_factory,
        )));
        tests.extend(shared_backend_tests(shared_backend_factory));
    }

    libtest_mimic::run(&args, tests)
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
