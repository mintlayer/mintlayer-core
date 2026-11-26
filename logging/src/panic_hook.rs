// Copyright (c) 2021-2026 RBB S.r.l
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
    any::Any,
    backtrace::{Backtrace, BacktraceStatus},
    panic::PanicHookInfo,
};

/// The panic message of payloads that are neither `&str` nor `String`.
const NON_STRING_PAYLOAD_MESSAGE: &str = "<non-string panic payload>";

/// Install a panic hook that reports every panic through the log at the error level.
///
/// The report contains the panic message, the file and line of the panic, the name of the
/// panicking thread and, when the `RUST_BACKTRACE` env var asks for one, a backtrace. The
/// hook that was installed before is called afterwards, so the default report on stderr is
/// kept.
///
/// Without this, a panic in a task that nobody joins is reported by nothing but the
/// runtime, and a panic in a joined task reaches the log only as the bare "task panicked"
/// error of the join, without the location and the message of the failure.
///
/// Calling this function again chains the hooks, so no previously installed report is lost.
pub fn install_panic_hook() {
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info: &PanicHookInfo<'_>| {
        // Note: the backtrace is captured here, in the hook, because the payload and the
        // location of the panic carry none; it starts at this hook rather than at the
        // panicking frame, but the frames below it are the ones that lead to the panic.
        // `capture` honors `RUST_BACKTRACE` like the default hook does: the binaries enable
        // it through `utils::enable_rust_backtrace`, while an explicit `RUST_BACKTRACE=0`
        // keeps the report short.
        let backtrace = Backtrace::capture();
        let backtrace = if backtrace.status() == BacktraceStatus::Captured {
            format!("\nBacktrace:\n{backtrace}")
        } else {
            String::new()
        };

        let thread_name = std::thread::current()
            .name()
            .map_or_else(|| "<unnamed>".to_owned(), str::to_owned);
        let location = panic_info
            .location()
            .map_or_else(|| "<unknown location>".to_owned(), ToString::to_string);

        log::error!(
            "Panic in thread '{thread_name}': {} at {location}{backtrace}",
            panic_message(panic_info.payload()),
        );

        previous_hook(panic_info);
    }));
}

fn panic_message(payload: &(dyn Any + Send)) -> &str {
    // Note: this is the same distinction that the default hook makes; a payload of any
    // other type can only be produced by `panic_any`.
    if let Some(message) = payload.downcast_ref::<&str>() {
        message
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message
    } else {
        NON_STRING_PAYLOAD_MESSAGE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn panic_hook_chains_to_the_previous_hook() {
        let previous_hook_calls = Arc::new(AtomicUsize::new(0));

        // Keep the hook of the test harness to restore it at the end.
        let harness_hook = std::panic::take_hook();

        // A stand-in for the default hook, to verify that the installed hook calls it.
        let calls = Arc::clone(&previous_hook_calls);
        std::panic::set_hook(Box::new(move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
        }));

        // Installing twice must chain the hooks instead of dropping the first one.
        install_panic_hook();
        install_panic_hook();

        let result = std::panic::catch_unwind(|| panic!("test panic"));
        assert!(result.is_err());

        // Restore the hook of the test harness so that the other tests keep their reports.
        drop(std::panic::take_hook());
        std::panic::set_hook(harness_hook);

        assert_eq!(previous_hook_calls.load(Ordering::SeqCst), 1);
    }
}
