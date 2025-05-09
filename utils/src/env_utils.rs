// Copyright (c) 2021-2025 RBB S.r.l
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

pub fn get_from_env(var_name: &str) -> Result<Option<String>, Error> {
    Ok(logging::get_from_env(var_name)?)
}

pub fn bool_from_env(var_name: &str) -> Result<Option<bool>, Error> {
    let Some(val) = get_from_env(var_name)? else {
        return Ok(None);
    };

    let true_vals = ["1", "yes", "true"];
    let false_vals = ["0", "no", "false"];

    if true_vals.iter().any(|true_val| val.eq_ignore_ascii_case(true_val)) {
        Ok(Some(true))
    } else if false_vals.iter().any(|false_val| val.eq_ignore_ascii_case(false_val)) {
        Ok(Some(false))
    } else {
        Err(Error::NonBoolValue {
            var_name: var_name.to_owned(),
            value: val,
        })
    }
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("Env var {var_name}'s value '{value}' cannot be interpreted as a bool")]
    NonBoolValue { var_name: String, value: String },

    #[error("Error obtaining env var value: {0}")]
    GetFromEnvError(#[from] logging::GetFromEnvError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bool_from_env() {
        let var_name = "TEST_BOOL_FROM_ENV_TEST_VAR_NAME";

        let result = bool_from_env(var_name);
        assert_eq!(result, Ok(None));

        let true_vals = ["1", "yes", "yEs", "true", "TruE"];
        let false_vals = ["0", "no", "nO", "false", "fALSE"];
        let bad_vals = ["2", "noo", "yess"];

        for val in true_vals {
            std::env::set_var(var_name, val);
            let result = bool_from_env(var_name);
            assert_eq!(result, Ok(Some(true)));
        }

        for val in false_vals {
            std::env::set_var(var_name, val);
            let result = bool_from_env(var_name);
            assert_eq!(result, Ok(Some(false)));
        }

        for val in bad_vals {
            std::env::set_var(var_name, val);
            let result = bool_from_env(var_name);
            assert_eq!(
                result,
                Err(Error::NonBoolValue {
                    var_name: var_name.to_owned(),
                    value: val.to_owned()
                })
            );
        }
    }
}
