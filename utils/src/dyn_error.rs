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

use std::any::Any;

/// `DynError` is a sub-trait of `Error` that implements `Eq`. Also, `Box<dyn DynError>`
/// implements `Clone`.
pub trait DynError: std::error::Error + Send + Sync {
    fn as_any(&self) -> &dyn Any;

    fn dyn_eq(&self, other: &dyn Any) -> bool;

    fn dyn_clone(&self) -> Box<dyn DynError>;
}

impl<T: 'static + std::error::Error + Eq + Clone + Send + Sync> DynError for T {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn dyn_eq(&self, other: &dyn Any) -> bool {
        other.downcast_ref::<T>().map_or(false, |t| self == t)
    }

    fn dyn_clone(&self) -> Box<dyn DynError> {
        Box::new(self.clone())
    }
}

impl PartialEq for dyn DynError {
    fn eq(&self, other: &Self) -> bool {
        self.dyn_eq(other.as_any())
    }
}

impl Eq for dyn DynError {}

// Note: without this strange impl, deriving `PartialEq` for types containing `Box<dyn DynError>`
// will fail with the error "cannot move out of `other` which is behind a shared reference".
// For details, see https://github.com/rust-lang/rust/issues/31740
// Here we use the workaround described in this comment - https://github.com/rust-lang/rust/issues/31740#issuecomment-700950186
// Note that the body of this `eq` doesn't seem to be ever called. So e.g. after changing it to
// `unimplemented!` the tests will still pass. But we want to be on the safer side.
impl PartialEq<&Self> for Box<dyn DynError> {
    fn eq(&self, other: &&Self) -> bool {
        self.dyn_eq(other.as_any())
    }
}

impl Clone for Box<dyn DynError> {
    fn clone(&self) -> Self {
        self.dyn_clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(thiserror::Error, Clone, Debug, PartialEq, Eq)]
    enum TestError1 {
        #[error("TestError1::Error1: {0}")]
        Error1(usize),
        #[error("TestError1::Error2: {0}")]
        Error2(String),
    }

    #[derive(thiserror::Error, Clone, Debug, PartialEq, Eq)]
    #[error("TestError2: {0}")]
    struct TestError2(char);

    #[derive(thiserror::Error, Clone, Debug, PartialEq, Eq)]
    #[error("Complex error: {0}")]
    struct ComplexError(Box<dyn DynError>);

    #[test]
    fn test() {
        let e1 = ComplexError(Box::new(TestError1::Error1(123)));
        let e2 = ComplexError(Box::new(TestError1::Error2("foo".to_owned())));
        let e3 = ComplexError(Box::new(TestError2('a')));
        assert_eq!(e1, e1.clone());
        assert_eq!(e2, e2.clone());
        assert_eq!(e3, e3.clone());
        assert_ne!(e1, e2);
        assert_ne!(e2, e1);
        assert_ne!(e1, e3);
        assert_ne!(e3, e1);
        assert_ne!(e2, e3);
        assert_ne!(e3, e2);

        assert_eq!(format!("{e1:?}"), "ComplexError(Error1(123))");
        assert_eq!(format!("{e2:?}"), "ComplexError(Error2(\"foo\"))");
        assert_eq!(format!("{e3:?}"), "ComplexError(TestError2('a'))");

        assert_eq!(format!("{e1}"), "Complex error: TestError1::Error1: 123");
        assert_eq!(format!("{e2}"), "Complex error: TestError1::Error2: foo");
        assert_eq!(format!("{e3}"), "Complex error: TestError2: a");
    }
}
