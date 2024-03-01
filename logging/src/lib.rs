// Copyright (c) 2021-2023 RBB S.r.l
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
mod tracing_utils;

use std::{
    io::{IsTerminal, Write},
    sync::Mutex,
};

use tracing_subscriber::{
    fmt::MakeWriter, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer, Registry,
};

use log_style::{get_log_style_from_env, LogStyle, TextColoring};

pub use log;

pub use tracing_utils::{spawn_in_current_span, spawn_in_span};

/// Send log output to the terminal.
pub fn init_logging() {
    init_logging_impl(
        // Write to stderr to mimic the behavior of env_logger.
        std::io::stderr,
        // This will be true if stderr is the actual terminal (i.e. it wasn't redirected
        // to a file etc).
        std::io::stderr().is_terminal(),
        // Use the default env var for filtering.
        None,
    );
}

/// Send log output to the specified [Write] instance, log lines are separated by '\n'
///
/// `is_terminal` will determine text coloring in the `TextColoring::Auto` case.
pub fn init_logging_to(file: impl Write + Send + 'static, is_terminal: bool) {
    init_logging_impl(Mutex::new(Box::new(file)), is_terminal, None);
}

/// Same as init_logging_to, but here we use the specified custom env var for filtering
/// instead of RUST_LOG.
pub fn init_logging_with_env_var(
    file: impl Write + Send + 'static,
    is_terminal: bool,
    filter_env_var_name: &str,
) {
    init_logging_impl(
        Mutex::new(Box::new(file)),
        is_terminal,
        Some(filter_env_var_name),
    );
}

static LOG_STYLE_ENV_VAR_NAME: &str = "ML_LOG_STYLE";

static INITIALIZE_LOGGER_ONCE_FLAG: std::sync::Once = std::sync::Once::new();

/// `filter_env_var_name` specifies a custom env var to use instead of RUST_LOG;
/// if not specified, RUST_LOG will be used.
fn init_logging_impl<MW>(make_writer: MW, is_terminal: bool, filter_env_var_name: Option<&str>)
where
    MW: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    INITIALIZE_LOGGER_ONCE_FLAG.call_once(move || {
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

        Registry::default()
            .with(logging_layer)
            // This will construct EnvFilter using the specified env variable.
            .with(EnvFilter::from_env(
                filter_env_var_name.unwrap_or("RUST_LOG"),
            ))
            // This basically calls tracing::subscriber::set_global_default on self and then
            // initializes a 'log' compatibility layer, so that 'log' macros continue to work
            // (this requires the "tracing-log" feature to be enabled, but it is enabled by default).
            .init();

        // Now that we've initialized logging somehow, we can complain about the env var parsing error,
        // if any.
        if let Some(err) = log_style_parse_err {
            log::error!("Couldn't get log style from {LOG_STYLE_ENV_VAR_NAME} - {err}");
        }
    });
}

fn can_use_coloring() -> bool {
    if cfg!(windows) {
        // Allow using colors if run in an MSYS console, which includes Git Bash
        // (the value of the variable will differ depending on how the console was started,
        // so we don't check it).
        // Also note that though Cygwin technically supports ansi coloring, it only works
        // in applications linked with cygwin.dll, so it makes no sense to check for it here
        // (which doesn't seem to be possible anyway).
        // Finally, we could enable ansi coloring for the traditional Windows console by using
        // this crate - https://github.com/sunshowers-code/enable-ansi-support
        // This will work only starting from Windows 10 though.
        std::env::var("MSYSTEM").is_ok()
    } else {
        true
    }
}

fn should_use_coloring(preferred_coloring: TextColoring, is_terminal: bool) -> bool {
    match preferred_coloring {
        TextColoring::On => true,
        TextColoring::Off => false,
        TextColoring::Auto => is_terminal && can_use_coloring(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_twice() {
        init_logging();
        init_logging();
    }
}
