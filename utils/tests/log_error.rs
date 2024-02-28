// Copyright (c) 2021-2024 RBB S.r.l
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

use log_output::LogOutput;
use logging::log;
use regex::Regex;
use thiserror::Error;
use utils::{log_error, tap_error_log::LogError};

#[derive(Error, Debug)]
#[error("This is serious")]
struct SeriousError;

// Note: since logging initialization is global, we can't have more than one test per
// integration test crate. So we put everything into one test.
#[tokio::test]
async fn test_all() {
    let output = LogOutput::new();
    output.init_logging();

    test_log_error_trait(&output);
    test_log_error_macro_non_async_funcs(&output);
    test_log_error_macro_async_funcs(&output).await;
}

fn assert_lines_match(output: &str, regexes: &[String], context: &str) {
    let output = output.trim();
    let lines = output.lines().collect::<Vec<_>>();

    for (line_idx, (line, regex)) in lines.iter().zip(regexes.iter()).enumerate() {
        assert!(
            Regex::new(regex).unwrap().is_match(line),
            "Wrong line in output ({context}, line_idx = {line_idx}): '{output}'\nThe regex was: '{regex}'"
        );
    }

    assert_eq!(
        lines.len(),
        regexes.len(),
        "Wrong number of lines in output ({context}): '{output}'"
    );
}

fn run_basic_tests(
    output: &LogOutput,
    context: &str,
    tests: &[(
        // test func
        &dyn Fn(/*whether test func should fail:*/ bool) -> Result<(), SeriousError>,
        // regex that the log output must match on error
        &[String],
    )],
) {
    for (idx, (test_func, regexes)) in tests.iter().enumerate() {
        {
            let _ = test_func(false).unwrap();
            let output = output.take();
            assert_eq!(output, "", "Wrong output ({context}, idx = {idx})");
        }

        {
            let _ = test_func(true).unwrap_err();
            let output = output.take();
            assert_lines_match(&output, regexes, &format!("{context}, idx = {idx}"));
        }
    }
}

mod test_log_error_trait_helpers {
    use super::*;

    pub fn failing_func(fail: bool) -> Result<(), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(())
        }
    }
}

fn test_log_error_trait(output: &LogOutput) {
    use test_log_error_trait_helpers::*;

    let tests: &[(&dyn Fn(bool) -> Result<(), SeriousError>, &[String])] = &[
        // log_err
        (
            &|fail| failing_func(fail).log_err(),
            &[format!(
                r"ERROR LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        // log_warn
        (
            &|fail| failing_func(fail).log_warn(),
            &[format!(
                r"WARN LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        // log_err_with_level
        (
            &|fail| failing_func(fail).log_err_with_level(log::Level::Trace),
            &[format!(
                r"TRACE LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| failing_func(fail).log_err_with_level(log::Level::Debug),
            &[format!(
                r"DEBUG LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| failing_func(fail).log_err_with_level(log::Level::Info),
            &[format!(
                r"INFO LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| failing_func(fail).log_err_with_level(log::Level::Warn),
            &[format!(
                r"WARN LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| failing_func(fail).log_err_with_level(log::Level::Error),
            &[format!(
                r"ERROR LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        // log_err_pfx
        (
            &|fail| failing_func(fail).log_err_pfx("foo"),
            &[format!(
                r"ERROR LogError: foo: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        // log_warn_pfx
        (
            &|fail| failing_func(fail).log_warn_pfx("foo"),
            &[format!(
                r"WARN LogError: foo: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        // log_err_with_level_pfx
        (
            &|fail| failing_func(fail).log_err_with_level_pfx(log::Level::Trace, "foo"),
            &[format!(
                r"TRACE LogError: foo: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| failing_func(fail).log_err_with_level_pfx(log::Level::Debug, "foo"),
            &[format!(
                r"DEBUG LogError: foo: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| failing_func(fail).log_err_with_level_pfx(log::Level::Info, "foo"),
            &[format!(
                r"INFO LogError: foo: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| failing_func(fail).log_err_with_level_pfx(log::Level::Warn, "foo"),
            &[format!(
                r"WARN LogError: foo: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| failing_func(fail).log_err_with_level_pfx(log::Level::Error, "foo"),
            &[format!(
                r"ERROR LogError: foo: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
    ];

    run_basic_tests(&output, "test_log_error_trait", &tests);
}

mod test_log_error_macro_non_async_funcs_helpers {
    use super::*;

    #[log_error]
    pub fn func_returns_unit(fail: bool) -> Result<(), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(())
        }
    }

    #[log_error]
    pub fn func_returns_i32(fail: bool) -> Result<i32, SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(42)
        }
    }

    #[log_error]
    pub fn func_with_early_return(fail: bool) -> Result<(), SeriousError> {
        if fail {
            return Err(SeriousError);
        }

        Ok(())
    }

    #[log_error]
    pub fn nested_funcs_innermost(fail: bool) -> Result<(), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(())
        }
    }

    pub const INNERMOST_FUNC_CALL_LINE: u32 = line!() + 4;

    #[log_error]
    pub fn nested_funcs_inner(fail: bool) -> Result<(), SeriousError> {
        nested_funcs_innermost(fail)
    }

    pub const INNER_FUNC_CALL_LINE: u32 = line!() + 4;

    #[log_error]
    pub fn nested_funcs_outer(fail: bool) -> Result<(), SeriousError> {
        nested_funcs_inner(fail)
    }

    #[log_error]
    #[tracing::instrument]
    pub fn func_with_tracing_instrument_inner(fail: bool) -> Result<(), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(())
        }
    }

    // Same as func_with_tracing_instrument_inner, but here the call to tracing::instrument comes first.
    #[tracing::instrument]
    #[log_error]
    pub fn func_with_tracing_instrument_outer(fail: bool) -> Result<(), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(())
        }
    }

    #[log_error(level = "trace")]
    pub fn func_log_level_trace1(fail: bool) -> Result<(), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(())
        }
    }

    #[log_error(level = "tRaCe")]
    pub fn func_log_level_trace2(fail: bool) -> Result<(), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(())
        }
    }

    #[log_error(level = "debug")]
    pub fn func_log_level_debug1(fail: bool) -> Result<(), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(())
        }
    }

    #[log_error(level = "dEbUg")]
    pub fn func_log_level_debug2(fail: bool) -> Result<(), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(())
        }
    }

    #[log_error(level = "info")]
    pub fn func_log_level_info1(fail: bool) -> Result<(), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(())
        }
    }

    #[log_error(level = "iNfO")]
    pub fn func_log_level_info2(fail: bool) -> Result<(), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(())
        }
    }

    #[log_error(level = "warn")]
    pub fn func_log_level_warn1(fail: bool) -> Result<(), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(())
        }
    }

    #[log_error(level = "wArN")]
    pub fn func_log_level_warn2(fail: bool) -> Result<(), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(())
        }
    }

    #[log_error(level = "error")]
    pub fn func_log_level_error1(fail: bool) -> Result<(), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(())
        }
    }

    #[log_error(level = "eRrOr")]
    pub fn func_log_level_error2(fail: bool) -> Result<(), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(())
        }
    }
}

fn test_log_error_macro_non_async_funcs(output: &LogOutput) {
    use test_log_error_macro_non_async_funcs_helpers::*;

    let tests: &[(&dyn Fn(bool) -> Result<(), SeriousError>, &[String])] = &[
        (
            &|fail| func_returns_unit(fail),
            &[format!(
                r"ERROR LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| func_returns_i32(fail).map(|_| ()),
            &[format!(
                r"ERROR LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| func_with_early_return(fail),
            &[format!(
                r"ERROR LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| nested_funcs_outer(fail),
            &[
                format!(
                    r"ERROR LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                    INNERMOST_FUNC_CALL_LINE
                ),
                format!(
                    r"ERROR LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                    INNER_FUNC_CALL_LINE
                ),
                format!(
                    r"ERROR LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                    line!() - 12
                ),
            ],
        ),
        (
            &|fail| func_with_tracing_instrument_inner(fail),
            &[format!(
                r"ERROR func_with_tracing_instrument_inner\{{fail=true\}}: LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            // Note: tracing span info is not included in this case.
            &|fail| func_with_tracing_instrument_outer(fail),
            &[format!(
                r"ERROR LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| func_log_level_trace1(fail),
            &[format!(
                r"TRACE LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| func_log_level_trace2(fail),
            &[format!(
                r"TRACE LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| func_log_level_debug1(fail),
            &[format!(
                r"DEBUG LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| func_log_level_debug2(fail),
            &[format!(
                r"DEBUG LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| func_log_level_info1(fail),
            &[format!(
                r"INFO LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| func_log_level_info2(fail),
            &[format!(
                r"INFO LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| func_log_level_warn1(fail),
            &[format!(
                r"WARN LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| func_log_level_warn2(fail),
            &[format!(
                r"WARN LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| func_log_level_error1(fail),
            &[format!(
                r"ERROR LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
        (
            &|fail| func_log_level_error2(fail),
            &[format!(
                r"ERROR LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 3
            )],
        ),
    ];

    run_basic_tests(&output, "test_log_error_macro_non_async_funcs", &tests)
}

mod test_log_error_macro_async_funcs_helpers {
    use super::*;

    #[log_error]
    pub async fn func_returns_unit(fail: bool) -> Result<(), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(())
        }
    }

    #[log_error]
    pub async fn func_returns_i32(fail: bool) -> Result<i32, SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(42)
        }
    }

    #[log_error]
    pub async fn func_with_early_return(fail: bool) -> Result<(), SeriousError> {
        if fail {
            return Err(SeriousError);
        }

        Ok(())
    }

    #[log_error]
    pub async fn nested_funcs_innermost(fail: bool) -> Result<(), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(())
        }
    }

    pub const INNERMOST_FUNC_CALL_LINE: u32 = line!() + 4;

    #[log_error]
    pub async fn nested_funcs_inner(fail: bool) -> Result<(), SeriousError> {
        nested_funcs_innermost(fail).await
    }

    pub const INNER_FUNC_CALL_LINE: u32 = line!() + 4;

    #[log_error]
    pub async fn nested_funcs_outer(fail: bool) -> Result<(), SeriousError> {
        nested_funcs_inner(fail).await
    }

    #[log_error]
    pub async fn func_with_refs(
        fail: bool,
        x: &str,
        y: &str,
    ) -> Result<(String, String), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok((x.to_owned(), y.to_owned()))
        }
    }

    #[log_error(level = "trace")]
    pub async fn func_log_level_trace(fail: bool) -> Result<(), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(())
        }
    }

    #[log_error]
    #[tracing::instrument]
    pub async fn func_with_tracing_instrument_inner(fail: bool) -> Result<(), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(())
        }
    }

    // Same as func_with_tracing_instrument_inner, but here the call to tracing::instrument comes first.
    #[tracing::instrument]
    #[log_error]
    pub async fn func_with_tracing_instrument_outer(fail: bool) -> Result<(), SeriousError> {
        if fail {
            Err(SeriousError)
        } else {
            Ok(())
        }
    }
}

async fn test_log_error_macro_async_funcs(output: &LogOutput) {
    use test_log_error_macro_async_funcs_helpers::*;

    // func_returns_unit
    {
        let _ = func_returns_unit(false).await.unwrap();
        assert_eq!(output.take(), "");
    }
    {
        let _ = func_returns_unit(true).await.unwrap_err();
        let output = output.take();
        assert_lines_match(
            &output,
            &[format!(
                r"ERROR LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 6
            )],
            "test_log_error_macro_async_funcs/func_returns_unit",
        );
    }

    // func_returns_i32
    {
        let _ = func_returns_i32(false).await.unwrap();
        assert_eq!(output.take(), "");
    }
    {
        let _ = func_returns_i32(true).await.unwrap_err();
        let output = output.take();
        assert_lines_match(
            &output,
            &[format!(
                r"ERROR LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 6
            )],
            "test_log_error_macro_async_funcs/func_returns_i32",
        );
    }

    // func_with_early_return
    {
        let _ = func_with_early_return(false).await.unwrap();
        assert_eq!(output.take(), "");
    }
    {
        let _ = func_with_early_return(true).await.unwrap_err();
        let output = output.take();
        assert_lines_match(
            &output,
            &[format!(
                r"ERROR LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 6
            )],
            "test_log_error_macro_async_funcs/func_with_early_return",
        );
    }

    // nested_funcs_outer
    {
        let _ = nested_funcs_outer(false).await.unwrap();
        assert_eq!(output.take(), "");
    }
    {
        let _ = nested_funcs_outer(true).await.unwrap_err();
        let output = output.take();
        assert_lines_match(
            &output,
            &[
                format!(
                    r"ERROR LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                    INNERMOST_FUNC_CALL_LINE
                ),
                format!(
                    r"ERROR LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                    INNER_FUNC_CALL_LINE
                ),
                format!(
                    r"ERROR LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                    line!() - 15
                ),
            ],
            "test_log_error_macro_async_funcs/nested_funcs_outer",
        );
    }

    // func_with_refs
    {
        let _ = func_with_refs(false, "foo", "bar").await.unwrap();
        assert_eq!(output.take(), "");
    }
    {
        let _ = func_with_refs(true, "foo", "bar").await.unwrap_err();
        let output = output.take();
        assert_lines_match(
            &output,
            &[format!(
                r"ERROR LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 6
            )],
            "test_log_error_macro_async_funcs/func_with_refs",
        );
    }

    // func_log_level_trace
    // Note that we only check one case of custom log level specification, for simplicity.
    // (the other cases are checked in the non-async test; here we mainly check that the correct
    // LogError's method is chosen in the async case too)
    {
        let _ = func_log_level_trace(false).await.unwrap();
        assert_eq!(output.take(), "");
    }
    {
        let _ = func_log_level_trace(true).await.unwrap_err();
        let output = output.take();
        assert_lines_match(
            &output,
            &[format!(
                r"TRACE LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 6
            )],
            "test_log_error_macro_async_funcs/func_with_tracing_instrument_outer",
        );
    }

    // func_with_tracing_instrument_inner
    {
        let _ = func_with_tracing_instrument_inner(false).await.unwrap();
        assert_eq!(output.take(), "");
    }
    {
        let _ = func_with_tracing_instrument_inner(true).await.unwrap_err();
        let output = output.take();
        assert_lines_match(
            &output,
            &[format!(
                r"ERROR func_with_tracing_instrument_inner\{{fail=true\}}: LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 6
            )],
            "test_log_error_macro_async_funcs/func_with_tracing_instrument_inner",
        );
    }

    // func_with_tracing_instrument_outer
    {
        let _ = func_with_tracing_instrument_outer(false).await.unwrap();
        assert_eq!(output.take(), "");
    }
    {
        let _ = func_with_tracing_instrument_outer(true).await.unwrap_err();
        let output = output.take();
        assert_lines_match(
            &output,
            // Note: tracing span info is not included in this case.
            &[format!(
                r"ERROR LogError: This is serious \(utils/tests/log_error.rs:{}:\d+\)",
                line!() - 7
            )],
            "test_log_error_macro_async_funcs/func_with_tracing_instrument_outer",
        );
    }
}

mod log_output {
    use std::{
        io,
        sync::{Arc, Mutex},
    };

    use logging::init_logging_with_env_var;

    #[derive(Clone)]
    pub struct LogOutput(Arc<Mutex<Vec<u8>>>);

    impl LogOutput {
        pub fn new() -> Self {
            Self(Arc::new(Mutex::new(Vec::new())))
        }

        pub fn init_logging(&self) {
            let env_var_name = "LOGGING_TEST_RUST_LOG_VAR";
            std::env::set_var(env_var_name, "trace");
            init_logging_with_env_var(self.clone(), false, env_var_name);
        }

        pub fn take(&self) -> String {
            let mut vec = self.0.lock().unwrap();
            String::from_utf8(std::mem::take(&mut vec)).unwrap()
        }
    }

    impl io::Write for LogOutput {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut vec = self.0.lock().unwrap();
            vec.extend(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
