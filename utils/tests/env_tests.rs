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

use test_utils::set_env_var;
use utils::env_utils::{self, bool_from_env};

// Note: `serial_test::serial` is redundant while there is only one test here, but it'll be
// required if more tests are added in the future, so we have it "just in case".
#[test]
#[serial_test::serial]
fn test_bool_from_env() {
    let var_name = "TEST_BOOL_FROM_ENV_TEST_VAR_NAME";

    let result = bool_from_env(var_name);
    assert_eq!(result, Ok(None));

    let true_vals = ["1", "yes", "yEs", "true", "TruE"];
    let false_vals = ["0", "no", "nO", "false", "fALSE"];
    let bad_vals = ["2", "noo", "yess"];

    for val in true_vals {
        set_env_var(var_name, val);
        let result = bool_from_env(var_name);
        assert_eq!(result, Ok(Some(true)));
    }

    for val in false_vals {
        set_env_var(var_name, val);
        let result = bool_from_env(var_name);
        assert_eq!(result, Ok(Some(false)));
    }

    for val in bad_vals {
        set_env_var(var_name, val);
        let result = bool_from_env(var_name);
        assert_eq!(
            result,
            Err(env_utils::Error::NonBoolValue {
                var_name: var_name.to_owned(),
                value: val.to_owned()
            })
        );
    }
}
