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

use crate::in_sink_write;

/// The panic message of payloads that are neither `&str` nor `String`.
const NON_STRING_PAYLOAD_MESSAGE: &str = "<non-string panic payload>";

/// Install a panic hook that reports every panic through the log at the error level.
///
/// The report contains the panic message, the file and line of the panic, the name of the
/// panicking thread and, when the `RUST_BACKTRACE` env var asks for one, a backtrace. The
/// hook that was installed before is called first, so the default report on stderr is
/// kept, whatever happens to the report through the log.
///
/// A panic inside a write to a log sink (for example in the rotation of the log file) is
/// reported to stderr only: the sink is written under a mutex that the panicking thread
/// holds until the unwinding releases it, so a report through the log would wait for it
/// forever, and the process would hang instead of aborting.
///
/// Without this, a panic in a task that nobody joins is reported by nothing but the
/// runtime, and a panic in a joined task reaches the log only as the bare "task panicked"
/// error of the join, without the location and the message of the failure.
///
/// Calling this function again chains the hooks, so no previously installed report is lost.
pub fn install_panic_hook() {
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info: &PanicHookInfo<'_>| {
        previous_hook(panic_info);
        report_panic(panic_info);
    }));
}

/// Reports a panic through the log, or to stderr when the panic occurred inside a log sink.
fn report_panic(panic_info: &PanicHookInfo<'_>) {
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

    let report = format!(
        "Panic in thread '{thread_name}': {} at {location}{backtrace}",
        panic_message(panic_info.payload()),
    );

    if in_sink_write() {
        eprintln!("{report}");
    } else {
        // This goes to the subscriber directly rather than through the `log` facade, whose
        // records need the compatibility layer that only the binaries install.
        tracing::error!("{report}");
    }
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
    use std::{
        io::Write as _,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    use crate::{
        LogStyle, MakeWriter as _, SinkWriteGuard, TextColoring, in_sink_write,
        test_utils::LogOutput, write_to_make_writer,
    };

    #[test]
    #[serial_test::serial]
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

        fn capture(output: &LogOutput, f: impl FnOnce()) -> String {
            output
                .capture(LogStyle::Text(TextColoring::Off), false, false, f)
                .trim()
                .to_owned()
        }
        let output = LogOutput::default();

        // Outside a sink, the report goes through the log, after the previous hook. The path
        // separator in the panic location is platform-dependent (`file!()` uses backslashes
        // on Windows).
        let report = capture(&output, || {
            let result = std::panic::catch_unwind(|| panic!("test panic"));
            assert!(result.is_err());
        });
        let report = report.replace('\\', "/");
        assert!(
            report.contains("Panic in thread 'panic_hook::tests::panic_hook_chains_to_the_previous_hook': test panic at logging/src/panic_hook.rs:"),
            "{report}"
        );
        assert_eq!(previous_hook_calls.load(Ordering::SeqCst), 1);

        // Inside a write to a sink the report must not go through the log: the thread
        // holds the lock of the sink until the unwinding releases it, and taking it again
        // would hang the hook (and with it the abort that follows). The previous hook is
        // still called.
        let report = capture(&output, || {
            let _guard = SinkWriteGuard::enter();
            assert!(in_sink_write());
            let result = std::panic::catch_unwind(|| panic!("test panic inside a sink write"));
            assert!(result.is_err());
        });
        assert!(report.is_empty(), "{report}");
        assert!(!in_sink_write());
        assert_eq!(previous_hook_calls.load(Ordering::SeqCst), 2);

        // Restore the hook of the test harness so that the other tests keep their reports.
        drop(std::panic::take_hook());
        std::panic::set_hook(harness_hook);
    }

    /// A writer that fails, standing in for a sink that fails in the middle of a write.
    struct FailingWriter(Arc<AtomicBool>);

    impl std::io::Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            self.0.store(in_sink_write(), Ordering::SeqCst);
            Err(std::io::Error::other("sink write failure"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn sink_write_marks_the_thread() {
        let inside_write = Arc::new(AtomicBool::new(false));
        let make_writer = write_to_make_writer(FailingWriter(Arc::clone(&inside_write)));

        // The mark covers the whole lock scope: from handing the writer out to dropping it.
        let mut writer = make_writer.make_writer();
        assert!(in_sink_write());

        let result = writer.write_all(b"line");
        assert!(result.is_err());
        assert!(inside_write.load(Ordering::SeqCst));
        assert!(in_sink_write());

        drop(writer);
        assert!(!in_sink_write());
    }
}
