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
    sync::Mutex,
};

use tracing_subscriber::{
    fmt::MakeWriter, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry,
};

pub use log;

pub fn is_only_terminal_output_logging() -> bool {
    true
}

pub fn is_file_output_supported() -> bool {
    false
}

static INITIALIZE_LOGGER_ONCE_FLAG: std::sync::Once = std::sync::Once::new();

fn init_logging_impl<MW>(make_writer: MW, enable_coloring: bool)
where
    MW: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    INITIALIZE_LOGGER_ONCE_FLAG.call_once(move || {
        Registry::default()
            .with(
                tracing_subscriber::fmt::Layer::new()
                    .with_writer(make_writer)
                    .with_ansi(enable_coloring),
            )
            // This will construct EnvFilter using the default env variable RUST_LOG
            .with(EnvFilter::from_default_env())
            // This basically calls tracing::subscriber::set_global_default on self and then
            // initializes a 'log' compatibility layer, so that 'log' macros continue to work
            // (this requires the "tracing-log" feature to be enabled, but it is enabled by default).
            .init();
    });
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
