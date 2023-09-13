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

mod log_style;

use std::{
    io::{IsTerminal, Write},
    sync::Mutex,
};

use log_style::{get_log_style_from_env, LogStyle, TextColoring};
use tracing_subscriber::{
    fmt::MakeWriter, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer, Registry,
};

pub use log;

pub fn is_only_terminal_output_logging() -> bool {
    true
}

pub fn is_file_output_supported() -> bool {
    false
}

/// Send log output to the terminal.
pub fn init_logging<P: AsRef<std::path::Path>>(_: Option<P>) {
    init_logging_impl(
        // Write to stderr to mimic the behavior of env_logger.
        std::io::stderr,
        // This will be true if stderr is the actual terminal (i.e. it wasn't redirected
        // to a file etc).
        std::io::stderr().is_terminal(),
    );
}

/// Send log output to the specified [Write] instance, log lines are separated by '\n'
///
/// `is_terminal` will determine text coloring in the `TextColoring::Auto` case.
pub fn init_logging_to(file: impl Write + Send + 'static, is_terminal: bool) {
    init_logging_impl(Mutex::new(Box::new(file)), is_terminal);
}

static LOG_STYLE_ENV_VAR_NAME: &str = "ML_LOG_STYLE";

static INITIALIZE_LOGGER_ONCE_FLAG: std::sync::Once = std::sync::Once::new();

fn init_logging_impl<MW>(make_writer: MW, is_terminal: bool)
where
    MW: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let (log_style, log_style_parse_err) = get_log_style_from_env(LOG_STYLE_ENV_VAR_NAME);

    let logging_layer: Box<dyn Layer<_> + Send + Sync> = match log_style {
        LogStyle::Json => {
            Box::new(tracing_subscriber::fmt::Layer::new().json().with_writer(make_writer))
        }
        LogStyle::Text(preferred_coloring) => Box::new(
            tracing_subscriber::fmt::Layer::new()
                .with_writer(make_writer)
                .with_ansi(should_use_coloring(preferred_coloring, is_terminal)),
        ),
    };

    INITIALIZE_LOGGER_ONCE_FLAG.call_once(move || {
        Registry::default()
            .with(logging_layer)
            // This will construct EnvFilter using the default env variable RUST_LOG
            .with(EnvFilter::from_default_env())
            // This basically calls tracing::subscriber::set_global_default on self and then
            // initializes a 'log' compatibility layer, so that 'log' macros continue to work
            // (this requires the "tracing-log" feature to be enabled, but it is enabled by default).
            .init();
    });

    // Now that we've initialized logging somehow, we can complain about the env var parsing error,
    // if any.
    if let Some(err) = log_style_parse_err {
        log::error!("Couldn't get log style from {LOG_STYLE_ENV_VAR_NAME} - {err}");
    }
}

fn should_use_coloring(preferred_coloring: TextColoring, is_terminal: bool) -> bool {
    match preferred_coloring {
        TextColoring::On => true,
        TextColoring::Off => false,
        TextColoring::Auto => is_terminal,
    }
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
