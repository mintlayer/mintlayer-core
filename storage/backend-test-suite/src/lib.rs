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

use prelude::*;

/// Get all tests
fn tests<B: Backend + ThreadSafe + Clone>(backend: B) -> Vec<libtest_mimic::Trial> {
    std::iter::empty()
        .chain(basic::tests(backend.clone()))
        .chain(concurrent::tests(backend.clone()))
        .chain(property::tests(backend))
        .collect()
}

/// Main test suite entry point
pub fn main<B: Backend + ThreadSafe + Clone>(backend: B) {
    let args = libtest_mimic::Arguments::from_args();
    libtest_mimic::run(&args, tests(backend)).exit();
}
