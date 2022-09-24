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

pub trait TypeName {
    fn typename_str() -> &'static str {
        // This implementation is good enough, though it includes the full qualifiers of a typename, which may not be ideal
        std::any::type_name::<Self>()
    }
}

impl TypeName for () {}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Eq, PartialEq, Debug)]
    struct TestType1;

    impl TypeName for TestType1 {}

    #[derive(Eq, PartialEq, Debug)]
    struct TestType2;

    impl TypeName for TestType2 {
        fn typename_str() -> &'static str {
            "TestType2"
        }
    }

    #[test]
    fn typename() {
        assert!(TestType1::typename_str().ends_with("TestType1"));
        assert_eq!(TestType2::typename_str(), "TestType2");
    }
}
