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

/// Set the `RUST_BACKTRACE` environment variable to `full` if it's not already set.
///
/// The macro must be called at the module scope, and the env var will be set before `main`
/// is entered.
///
/// Note: setting env vars is not safe in a multithreaded environment on *nix systems, so:
/// 1) It's not safe to set them in a `#[tokio::main]` function if a multithreaded runtime is used,
///    which is why we wrapped the call to `std::env::set_var` in a module-level macro.
/// 2) The macro itself is not safe if called in a dynamic library that can be loaded later
///    via `dlopen`. Though we always use static linking at the moment, it's better to avoid
///    calling this macro at a library level; call it inside "bin" crates only, preferably
///    near the `main` function.
///
/// Also note that the macro uses the `ctor` crate under the hood, so packages that use the macro
/// have to explicitly depend on `ctor`.
#[macro_export]
macro_rules! enable_rust_backtrace {
    () => {
        ctor::declarative::ctor! {
            #[ctor]
            fn rust_backtrace_enabler() {
                if std::env::var("RUST_BACKTRACE").is_err() {
                    unsafe {
                        std::env::set_var("RUST_BACKTRACE", "full");
                    }
                }
            }
        }
    };
}
