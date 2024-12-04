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

mod basic;
pub mod podman;

#[macro_use]
pub mod helpers;

use api_server_common::storage::storage_api::ApiServerStorage;
use futures::Future;
use std::sync::Arc;

/// Get all tests
fn tests<S, Fut, F: Fn() -> Fut + Send + Sync + 'static>(
    storage_maker: F,
) -> Vec<libtest_mimic::Trial>
where
    Fut: Future<Output = S> + Send + 'static,
    S: ApiServerStorage + 'static,
{
    let storage_maker = Arc::new(storage_maker);
    std::iter::empty()
        .chain(basic::build_tests(storage_maker))
        // .chain(concurrent::tests(Arc::clone(&backend_fn)))
        // .chain(property::tests(backend_fn))
        .collect()
}

/// Main test suite entry point
#[must_use = "Test outcome ignored, add a call to .exit()"]
pub fn run<S, Fut, F: Fn() -> Fut + Send + Sync + 'static>(
    storage_maker: F,
) -> libtest_mimic::Conclusion
where
    Fut: Future<Output = S> + Send + 'static,
    S: ApiServerStorage + 'static,
{
    logging::init_logging();
    let args = libtest_mimic::Arguments::from_args();
    libtest_mimic::run(&args, tests(storage_maker))
}
