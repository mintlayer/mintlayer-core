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
mod utils;

use std::{
    io::{IsTerminal, Write},
    sync::Mutex,
};

use tracing::{level_filters::LevelFilter, Subscriber};
use tracing_subscriber::{
    fmt::MakeWriter, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer, Registry,
};

use log_style::{get_log_style_from_env, LogStyleParseError};

pub use log;
pub use log_style::{LogStyle, TextColoring};
pub use utils::{get_from_env, GetFromEnvError, ValueOrEnvVar};

/// Send log output to the terminal.
pub fn init_logging() {
    init_logging_generic(default_writer_settings(), no_writer_settings());
}

/// Send log output to the specified [Write] instance, log lines are separated by '\n'
///
/// `is_terminal` will determine text coloring in the `TextColoring::Auto` case.
pub fn init_logging_to(file: impl Write + Send + 'static, is_terminal: bool) {
    init_logging_generic(
        WriterSettings {
            make_writer: write_to_make_writer(file),
            is_terminal,
            filter: ValueOrEnvVar::EnvVar("RUST_LOG".into()),
            log_style: ValueOrEnvVar::EnvVar(LOG_STYLE_ENV_VAR_NAME.into()),
        },
        no_writer_settings(),
    );
}

pub fn default_writer_settings() -> WriterSettings<fn() -> std::io::Stderr> {
    WriterSettings {
        // Write to stderr to mimic the behavior of env_logger.
        make_writer: std::io::stderr,
        // This will be true if stderr is the actual terminal (i.e. it wasn't redirected
        // to a file etc).
        is_terminal: std::io::stderr().is_terminal(),
        // Use the default env var for filtering.
        filter: ValueOrEnvVar::EnvVar("RUST_LOG".into()),
        // Use the default env var for style.
        log_style: ValueOrEnvVar::EnvVar(LOG_STYLE_ENV_VAR_NAME.into()),
    }
}

/// Convert a `Write` instance to `MakeWriter`.
pub fn write_to_make_writer(
    writer: impl Write + Send + 'static,
) -> impl for<'a> MakeWriter<'a> + Send + Sync + 'static {
    Mutex::new(Box::new(writer))
}

static LOG_STYLE_ENV_VAR_NAME: &str = "ML_LOG_STYLE";
static DEFAULT_LOG_STYLE: LogStyle = LogStyle::Text(TextColoring::Auto);

static INITIALIZE_LOGGER_ONCE_FLAG: std::sync::Once = std::sync::Once::new();

pub struct WriterSettings<MW> {
    pub make_writer: MW,
    pub is_terminal: bool,
    pub filter: ValueOrEnvVar<String>,
    pub log_style: ValueOrEnvVar<LogStyle>,
}

/// Generic version of init_logging that allows to have an auxiliary writer with its own settings
/// for filtering and log style.
pub fn init_logging_generic<MW1, MW2>(
    main_writer_settings: WriterSettings<MW1>,
    aux_writer_settings: Option<WriterSettings<MW2>>,
) where
    MW1: for<'a> MakeWriter<'a> + Send + Sync + 'static,
    MW2: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    INITIALIZE_LOGGER_ONCE_FLAG.call_once(move || {
        let mut errors = Vec::new();
        let main_layer = make_layer(main_writer_settings, &mut errors);
        let aux_layer = aux_writer_settings.map(|settings| make_layer(settings, &mut errors));
        let tokio_console_layer = make_tokio_console_layer();

        Registry::default()
            .with(main_layer)
            .with(aux_layer)
            .with(tokio_console_layer)
            // This basically calls tracing::subscriber::set_global_default on self and then
            // initializes a 'log' compatibility layer, so that 'log' macros continue to work
            // (this requires the "tracing-log" feature to be enabled, but it is enabled by default).
            .init();

        // Now that we've initialized logging somehow, we can complain about errors, if any.
        for error in errors {
            log::error!("Log initialization error: {error}");
        }
    });
}

pub fn no_writer_settings() -> Option<WriterSettings<tracing_subscriber::fmt::TestWriter>> {
    None
}

fn make_tokio_console_layer<S>() -> Option<Box<dyn Layer<S> + Send + Sync>>
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    // Note: `spawn` calls `Builder::with_default_env`, which reads config values (such as the bind
    // address) from a number of env vars, see:
    // https://github.com/tokio-rs/console/blob/console-subscriber-v0.5.0/console-subscriber/src/builder.rs#L314-L321
    // Also note: if we ever decide to enable tokio-console support permanently (and switch it on/off via command
    // line arguments), then this env-based configuration should better be disabled.
    #[cfg(feature = "tokio-console")]
    return Some(console_subscriber::spawn().boxed());

    #[cfg(not(feature = "tokio-console"))]
    return None;
}

fn make_layer<MW, S>(
    writer_settings: WriterSettings<MW>,
    errors: &mut Vec<InternalLogInitError>,
) -> Box<dyn Layer<S> + Send + Sync>
where
    MW: for<'a> MakeWriter<'a> + Send + Sync + 'static,
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    let filter = make_env_filter(writer_settings.filter, errors);
    let log_style = get_log_style(&writer_settings.log_style, errors);

    make_layer_impl(
        writer_settings.make_writer,
        writer_settings.is_terminal,
        filter,
        log_style,
    )
}

fn make_layer_impl<MW, S>(
    make_writer: MW,
    is_terminal: bool,
    filter: EnvFilter,
    log_style: LogStyle,
) -> Box<dyn Layer<S> + Send + Sync>
where
    MW: for<'a> MakeWriter<'a> + Send + Sync + 'static,
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    match log_style {
        LogStyle::Json => tracing_subscriber::fmt::Layer::new()
            .json()
            .with_writer(make_writer)
            .with_filter(filter)
            .boxed(),
        LogStyle::Text(preferred_coloring) => tracing_subscriber::fmt::Layer::new()
            .with_writer(make_writer)
            .with_ansi(should_use_coloring(preferred_coloring, is_terminal))
            .with_filter(filter)
            .boxed(),
    }
}

fn get_log_style(
    log_style: &ValueOrEnvVar<LogStyle>,
    errors: &mut Vec<InternalLogInitError>,
) -> LogStyle {
    let result_opt = match get_log_style_impl(log_style) {
        Ok(opt_val) => opt_val,
        Err(err) => {
            errors.push(err);
            None
        }
    };
    result_opt.unwrap_or(DEFAULT_LOG_STYLE)
}

fn get_log_style_impl(
    log_style: &ValueOrEnvVar<LogStyle>,
) -> Result<Option<LogStyle>, InternalLogInitError> {
    match log_style {
        ValueOrEnvVar::Value(val) => Ok(Some(*val)),
        ValueOrEnvVar::EnvVar(var_name) => get_log_style_from_env(var_name).map_err(|err| {
            InternalLogInitError::LogStyleFromEnvRetrievalError {
                env_var_name: var_name.to_string(),
                error: err,
            }
        }),
    }
}

fn make_env_filter(
    filter_str: ValueOrEnvVar<String>,
    errors: &mut Vec<InternalLogInitError>,
) -> EnvFilter {
    let result_opt = match make_env_filter_impl(filter_str) {
        Ok(filter) => Some(filter),
        Err(err) => {
            errors.push(err);
            None
        }
    };

    result_opt.unwrap_or_else(|| {
        EnvFilter::builder()
            .with_default_directive(default_filter_directive())
            .parse_lossy("")
    })
}

fn make_env_filter_impl(filter: ValueOrEnvVar<String>) -> Result<EnvFilter, InternalLogInitError> {
    let filter_directives = match filter {
        ValueOrEnvVar::Value(val) => Some(val),
        ValueOrEnvVar::EnvVar(var_name) => get_from_env(var_name.as_ref())?,
    };
    let filter_directives = filter_directives.unwrap_or_default();

    // Note: here we try to catch errors to later print them to the log with the "error" severity, so that
    // typos in the filter string can be noticed. But not all errors will be caught. E.g. if you set the filter
    // to "debugg" instead of "debug", `parse` will treat it as a target and not as a log level, and nothing will
    // be printed to the log.
    let filter = EnvFilter::builder()
        // Default filter to use if the passed directives are empty (i.e. if the whole string is empty or it contains
        // a list of empty directives, e.g. something like ",,,").
        .with_default_directive(default_filter_directive())
        .parse(&filter_directives)
        .map_err(|err| InternalLogInitError::FilterDirectivesParseError {
            directives: filter_directives,
            error: err,
        })?;

    Ok(filter)
}

// Note: EnvFilter::from_env also uses ERROR as the default.
fn default_filter_directive() -> tracing_subscriber::filter::Directive {
    LevelFilter::ERROR.into()
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, thiserror::Error)]
enum InternalLogInitError {
    #[error("Error retrieving log style from env var {env_var_name}: {error}")]
    LogStyleFromEnvRetrievalError {
        env_var_name: String,
        error: LogStyleParseError,
    },

    #[error("Env var error: {0:?}")]
    GetFromEnvError(#[from] GetFromEnvError),

    #[error("Error parsing filter directives '{directives}': {error}")]
    FilterDirectivesParseError {
        directives: String,
        error: tracing_subscriber::filter::ParseError,
    },
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
