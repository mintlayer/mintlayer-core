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

// Re-export a bunch of often used items
pub use std::mem::drop;
pub use storage_core::{
    backend::{Backend, Data, ReadOps, TransactionalRo, TransactionalRw, TxRo, TxRw, WriteOps},
    info::{self, DbDesc, DbIndex, MapDesc},
};
pub use utils::{sync, thread};

pub use std::sync::Arc;

/// Alias for `Send + Sync + 'static`
pub trait ThreadSafe: std::panic::UnwindSafe + Send + Sync + 'static {}
impl<T: std::panic::UnwindSafe + Send + Sync + 'static> ThreadSafe for T {}

pub const IDX: (DbIndex, DbIndex) = (DbIndex::new(0), DbIndex::new(1));

/// Sample datbase decription with `n` maps
pub fn desc(n: usize) -> DbDesc {
    (0..n).map(|x| MapDesc::new(format!("map_{:02}", x))).collect()
}

/// Run tests with backend using proptest
pub fn using_proptest<B: Backend + ThreadSafe + Clone, S: proptest::prelude::Strategy>(
    source_file: &'static str,
    backend: B,
    strategy: S,
    test: impl Fn(B, S::Value),
) {
    let config = proptest::prelude::ProptestConfig::with_source_file(source_file);
    let mut runner = proptest::test_runner::TestRunner::new(config);
    let result = runner.run(&strategy, |val| {
        test(backend.clone(), val);
        Ok(())
    });
    result.unwrap_or_else(|e| panic!("{}{}", &e, &runner))
}

/// Test helper function not exported with the prelude
pub mod support {
    use super::*;
    use libtest_mimic::Trial;

    /// Create the test list
    pub fn create_tests<B: Backend + ThreadSafe + Clone>(
        backend: B,
        tests: impl IntoIterator<Item = (&'static str, fn(B))>,
    ) -> impl Iterator<Item = Trial> {
        tests.into_iter().map(move |(name, test)| {
            let backend = backend.clone();
            let test_fn = move || {
                utils::concurrency::model(move || test(backend.clone()));
                Ok(())
            };
            Trial::test(name, test_fn)
        })
    }
}

macro_rules! tests {
    ($($name:ident),* $(,)?) => {
        pub fn tests<B: crate::prelude::Backend + crate::prelude::ThreadSafe + Clone>(
            backend: B,
        ) -> impl std::iter::Iterator<Item = libtest_mimic::Trial> {
            crate::prelude::support::create_tests(backend, [
                $((concat!(module_path!(), "::", stringify!($name)), $name as fn(B)),)*
            ])
        }
    }
}
