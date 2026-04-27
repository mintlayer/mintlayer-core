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

use logging::{get_log_style_from_env, LogStyle, LogStyleParseError, TextColoring};
use test_utils::{remove_env_var, set_env_var};

static TEST_ENV_VAR: &str = "LOG_STYLE_TEST_ENV_VAR";

// Note: `serial_test::serial` is redundant while there is only one test here, but it'll be
// required if more tests are added in the future, so we have it "just in case".
#[test]
#[serial_test::serial]
fn parse_log_style_env_var() {
    // Basic tests
    {
        set_env_var(TEST_ENV_VAR, "text");
        let result = get_log_style_from_env(TEST_ENV_VAR);
        assert_eq!(result, Ok(Some(LogStyle::Text(TextColoring::Auto))));

        set_env_var(TEST_ENV_VAR, "text-colored");
        let result = get_log_style_from_env(TEST_ENV_VAR);
        assert_eq!(result, Ok(Some(LogStyle::Text(TextColoring::On))));

        set_env_var(TEST_ENV_VAR, "text-uncolored");
        let result = get_log_style_from_env(TEST_ENV_VAR);
        assert_eq!(result, Ok(Some(LogStyle::Text(TextColoring::Off))));

        set_env_var(TEST_ENV_VAR, "json");
        let result = get_log_style_from_env(TEST_ENV_VAR);
        assert_eq!(result, Ok(Some(LogStyle::Json)));
    }

    // Case-insensitivity tests
    {
        set_env_var(TEST_ENV_VAR, "tEXt");
        let result = get_log_style_from_env(TEST_ENV_VAR);
        assert_eq!(result, Ok(Some(LogStyle::Text(TextColoring::Auto))));

        set_env_var(TEST_ENV_VAR, "tEXt-coLoRed");
        let result = get_log_style_from_env(TEST_ENV_VAR);
        assert_eq!(result, Ok(Some(LogStyle::Text(TextColoring::On))));

        set_env_var(TEST_ENV_VAR, "tEXt-uncoLoRed");
        let result = get_log_style_from_env(TEST_ENV_VAR);
        assert_eq!(result, Ok(Some(LogStyle::Text(TextColoring::Off))));

        set_env_var(TEST_ENV_VAR, "jSoN");
        let result = get_log_style_from_env(TEST_ENV_VAR);
        assert_eq!(result, Ok(Some(LogStyle::Json)));
    }

    // Bad value test
    {
        let str = "foo";
        set_env_var(TEST_ENV_VAR, str);
        let result = get_log_style_from_env(TEST_ENV_VAR);
        assert_eq!(
            result,
            Err(LogStyleParseError::UnrecognizedFormat(str.to_owned()))
        );
    }

    // Missing value test
    {
        remove_env_var(TEST_ENV_VAR);
        let result = get_log_style_from_env(TEST_ENV_VAR);
        assert_eq!(result, Ok(None));
    }
}
