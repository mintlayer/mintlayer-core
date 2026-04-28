// Copyright (c) 2026 RBB S.r.l
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

//! Wrappers for `std::env::set_var` and `remove_var` to avoid writing `unsafe` every time.
//!
//! Note: `std::env::set_var` and `remove_var` are unsafe since Rust 2024, but they've never been
//! actually safe to use on *nix systems in a multithreaded context because reading/writing
//! env vars (even different ones) is not thread-safe (the `std::env` functions do use a lock
//! internally, but an env var can potentially be read by any function from `libc`, which may
//! potentially be called by any function from the std lib). In production code we avoid this problem
//! by only modifying env vars before `main` is entered (at which point there is only one thread),
//! but in tests we sometimes need to do this in a test's body directly (e.g. to check that the
//! tested code reads the environment properly) and tests are run in parallel by default.
//! So, careless use of these functions may lead to flaky tests. To avoid it:
//! 1) Serialize the tests, by putting e.g. `#[serial_test::serial(env)]` on all environment-modifying
//!    tests. But note that you'll also have to put `#[serial_test::parallel(env)]` on all other tests
//!    belonging to the same test executable, to ensure that they can only run in parallel with
//!    themselves, but not with those marked as "serial(env)".
//! 2) Consider putting environment-modifying tests into a separate integration test.

use std::ffi::OsStr;

pub fn set_env_var<K: AsRef<OsStr>, V: AsRef<OsStr>>(key: K, value: V) {
    unsafe {
        std::env::set_var(key, value);
    }
}

pub fn remove_env_var<K: AsRef<OsStr>>(key: K) {
    unsafe {
        std::env::remove_var(key);
    }
}
