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

pub use typename_derive::TypeName;

/// The interface for getting a name of the type.
///
/// The name is used in debug output, so it shouldn't be too verbose (fully qualified) to nut
/// clutter logs.
pub trait TypeName {
    /// Returns a name of the type.
    fn typename_str() -> &'static str;
}

impl TypeName for () {
    fn typename_str() -> &'static str {
        "()"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typename_manual() {
        struct TestType1;

        impl TypeName for TestType1 {
            fn typename_str() -> &'static str {
                "TestType1"
            }
        }

        assert_eq!(TestType1::typename_str(), "TestType1");
    }

    #[test]
    fn typename_derive() {
        #[derive(TypeName)]
        struct TestType2;

        assert_eq!(TestType2::typename_str(), "TestType2");
    }
}
