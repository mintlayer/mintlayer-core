// Copyright (c) 2021-2025 RBB S.r.l
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

use std::{
    backtrace::{Backtrace, BacktraceStatus},
    cell::Cell,
    thread::{self, JoinHandle},
};

use logging::log;

/// Spawn a new thread; if the thread panics, abort the process immediately.
pub fn spawn_thread_aborting_on_panic<F, R>(func: F) -> JoinHandle<R>
where
    F: FnOnce() -> R + Send + std::panic::UnwindSafe + 'static,
    R: Send + 'static,
{
    thread::spawn(move || {
        match std::panic::catch_unwind(func) {
            Ok(result) => result,
            Err(err) => {
                let backtrace =
                    THREAD_LOCAL_BACKTRACE.with(|b| b.take()).expect("must be set by panic hook");

                // Note: downcasting to `&str` is needed to catch panics like `panic!("foo")`.
                // And downcasting to `String` is needed to catch those like `panic!("{}", "foo")`.
                let msg = err
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| err.downcast_ref::<String>().map(AsRef::as_ref))
                    .unwrap_or("???");
                let backtrace = match backtrace.status() {
                    BacktraceStatus::Captured => backtrace.to_string(),
                    BacktraceStatus::Disabled => {
                        "  ** Backtrace disabled, set the RUST_BACKTRACE env var (e.g. to 'full') **"
                            .to_owned()
                    }
                    BacktraceStatus::Unsupported => "  ** Backtrace unsupported **".to_owned(),
                    _ => "  ** Unknown backtrace status **".to_owned(),
                };
                log::error!(
                    "The thread panicked with message:\n  {msg}\nand backtrace:\n{backtrace}",
                );
                std::process::abort();
            }
        }
    })
}

// A hack to be able to get the backtrace if the func passed to `spawn_thread_aborting_on_panic` panics.
thread_local! {
    static THREAD_LOCAL_BACKTRACE: Cell<Option<Backtrace>> = const { Cell::new(None) };
}

fn setup_panic_handling() {
    let old_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let trace = Backtrace::capture();
        THREAD_LOCAL_BACKTRACE.with(move |b| b.set(Some(trace)));
        old_panic_hook(panic_info);
    }));
}

#[ctor::ctor]
fn init() {
    setup_panic_handling();
}
