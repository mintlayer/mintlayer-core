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

use std::{
    io::{IsTerminal, Write},
    ops::DerefMut,
    sync::Mutex,
};

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    filter::LevelFilter, fmt::MakeWriter, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
    Layer, Registry,
};

pub use log;

pub fn is_only_terminal_output_logging() -> bool {
    true
}

pub fn is_file_output_supported() -> bool {
    false
}

static INITIALIZE_LOGGER_ONCE_FLAG: std::sync::Once = std::sync::Once::new();

static FILE_LOG_WORKER_GUARD: Mutex<Option<WorkerGuard>> = Mutex::new(None);

// This function will create 2 logging layers:
// 1) The "normal" one, whose level is controlled via RUST_LOG and which writes the records using
// the provided "make_writer".
// 2) An additional layer, which has a fixed level and which writes the logs in JSON format
// to files at a predefined location.
fn init_logging_impl<MW>(make_writer: MW, enable_coloring: bool)
where
    MW: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    INITIALIZE_LOGGER_ONCE_FLAG.call_once(move || {
        // FIXME: this "rolling writer" doesn't have a limit on file size and doesn't delete old
        // files either, so we'll have to manage that ourselves.
        // (Note: "daily" means that a new file will be created each day; there are also the
        // "hourly", "minutely" and "never" variants).
        // There is a 3rd-party alternative though - https://docs.rs/rolling-file/0.2.0/rolling_file/
        // which is supposed to be better. Or we can write our own.
        let file_writer = tracing_appender::rolling::daily("/tmp/mintlayer_logs", log_file_name());
        // The "NonBlocking" writer will spawn a dedicated worker thread for writing via
        // the specified writer.
        let (non_blocking_file_writer, file_writer_worker_guard) =
            tracing_appender::non_blocking::NonBlockingBuilder::default()
                // Do not drop records if the queue becomes full (and block the sender instead,
                // until the queue has capacity again).
                .lossy(false)
                .finish(file_writer);

        Registry::default()
            .with(
                // The "normal" layer.
                tracing_subscriber::fmt::Layer::new()
                    .with_writer(make_writer)
                    .with_ansi(enable_coloring)
                    // This will construct EnvFilter using the default env variable RUST_LOG
                    .with_filter(EnvFilter::from_default_env()),
            )
            .with(
                // The additional layer.
                tracing_subscriber::fmt::Layer::new()
                    .json()
                    .with_writer(non_blocking_file_writer)
                    .with_ansi(false)
                    // FIXME: Provided that old logs are not deleted automatically, DEBUG may
                    // be too verbose. Also, we might want to make this configurable as well
                    // (though I wouldn't re-use RUST_LOG for this).
                    .with_filter(LevelFilter::DEBUG),
            )
            // This basically calls tracing::subscriber::set_global_default on self and then
            // initializes a 'log' compatibility layer, so that 'log' macros continue to work
            // (this requires the "tracing-log" feature to be enabled, but it is enabled by default).
            .init();

        // Logging will stop if this guard is dropped, so we have to keep it in a static variable.
        let mut guard_lock = FILE_LOG_WORKER_GUARD.lock().expect("Mutex is poisoned");
        *guard_lock.deref_mut() = Some(file_writer_worker_guard);
    });
}

// Use the exe file name as the log file name if possible.
// FIXME: probably, we should avoid creating log files for tests, but I'm not sure it's
// possible to detect whether we're running an integration test.
fn log_file_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.file_name().map(|name| name.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "unknown_exe".into())
}

pub fn init_logging<P: AsRef<std::path::Path>>(_log_file_path: Option<P>) {
    init_logging_impl(
        // Write to stderr to mimic the behavior of env_logger.
        std::io::stderr,
        // Use output coloring only if stderr is a terminal (i.e. it wasn't redirected
        // to a file etc).
        std::io::stderr().is_terminal(),
    );
}

/// Send log output to the specified [Write] instance, log lines are separated by '\n'
pub fn init_logging_pipe(file: impl Write + Send + 'static, enable_coloring: bool) {
    init_logging_impl(Mutex::new(Box::new(file)), enable_coloring);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_twice() {
        init_logging::<&std::path::Path>(None);
        init_logging::<&std::path::Path>(None);
    }
}
