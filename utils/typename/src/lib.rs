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
    fn typename_str() -> std::borrow::Cow<'static, str>;
}

impl TypeName for () {
    fn typename_str() -> std::borrow::Cow<'static, str> {
        "()".into()
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use super::*;

    struct TestType1;

    impl TypeName for TestType1 {
        fn typename_str() -> std::borrow::Cow<'static, str> {
            "TestType1".into()
        }
    }

    #[test]
    fn typename_manual() {
        assert_eq!(TestType1::typename_str(), "TestType1");
    }

    #[derive(TypeName)]
    struct TestType2;

    #[test]
    fn typename_derive() {
        assert_eq!(TestType2::typename_str(), "TestType2");
    }

    struct TestType3<T> {
        _phantom: PhantomData<T>,
    }

    impl<T: TypeName> TypeName for TestType3<T> {
        fn typename_str() -> std::borrow::Cow<'static, str> {
            std::borrow::Cow::Owned("TestType3<".to_owned() + T::typename_str().as_ref() + ">")
        }
    }

    #[test]
    fn typename_with_custom_generic() {
        assert_eq!(
            TestType3::<TestType2>::typename_str(),
            "TestType3<TestType2>"
        );
    }

    #[derive(TypeName)]
    struct TestType4<T> {
        _phantom: PhantomData<T>,
    }

    #[test]
    fn typename_with_derived_generic() {
        assert_eq!(
            TestType4::<TestType2>::typename_str(),
            "TestType4<TestType2>"
        );
    }

    #[test]
    fn typename_with_derived_generic_generic() {
        assert_eq!(
            TestType4::<TestType3<TestType2>>::typename_str(),
            "TestType4<TestType3<TestType2>>"
        );
    }

    #[derive(TypeName)]
    struct TestType5<T, U> {
        _phantom1: PhantomData<T>,
        _phantom2: PhantomData<U>,
    }

    #[test]
    fn typename_with_two_generics() {
        assert_eq!(
            TestType5::<TestType2, TestType1>::typename_str(),
            "TestType5<TestType2,TestType1>"
        );
    }

    #[test]
    fn typename_for_enum() {
        #[derive(TypeName)]
        #[allow(dead_code)]
        enum TestType6 {
            A(u32),
            B(String),
        }

        assert_eq!(TestType6::typename_str(), "TestType6");
    }

    #[test]
    fn typename_for_enum_with_generic() {
        #[derive(TypeName)]
        #[allow(dead_code)]
        enum TestType7<T> {
            A(T),
            B(String),
        }

        assert_eq!(
            TestType7::<TestType2>::typename_str(),
            "TestType7<TestType2>"
        );
    }

    #[test]
    fn typename_for_enum_with_two_generics() {
        #[derive(TypeName)]
        #[allow(dead_code)]
        enum TestType8<T, U> {
            A(T),
            B(U),
        }

        assert_eq!(
            TestType8::<TestType2, TestType1>::typename_str(),
            "TestType8<TestType2,TestType1>"
        );
    }
}
