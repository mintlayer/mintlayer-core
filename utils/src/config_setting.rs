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

#[macro_export]
macro_rules! make_config_setting {
    ($name: ident, $tp: ty, $default_value: expr) => {
        #[derive(Debug, Clone)]
        pub struct $name {
            value: $tp,
        }

        impl From<$tp> for $name {
            fn from(v: $tp) -> Self {
                Self { value: v }
            }
        }

        impl From<$name> for $tp {
            fn from(v: $name) -> Self {
                v.value
            }
        }

        /// This is used to covert from "no value supplied from user in program options" to "default value"
        impl From<Option<$tp>> for $name {
            fn from(v: Option<$tp>) -> Self {
                Self {
                    value: v.unwrap_or(Self::default().value),
                }
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self {
                    value: $default_value,
                }
            }
        }

        impl std::ops::Deref for $name {
            type Target = $tp;

            fn deref(&self) -> &Self::Target {
                &self.value
            }
        }

        impl AsRef<$tp> for $name {
            fn as_ref(&self) -> &$tp {
                &self.value
            }
        }
    };
}

mod tests {
    make_config_setting!(MySetting, String, "DefaultValue".into());

    #[test]
    fn basic_defaults_and_loading() {
        let setting = MySetting::default();
        assert_eq!(*setting, "DefaultValue");

        let setting = MySetting::from(None);
        assert_eq!(*setting, "DefaultValue");

        let setting = MySetting::from(Some("MyValue".to_string()));
        assert_eq!(*setting, "MyValue");

        let setting = MySetting::from("MyOtherValue".to_string());
        assert_eq!(*setting, "MyOtherValue");
    }
}
