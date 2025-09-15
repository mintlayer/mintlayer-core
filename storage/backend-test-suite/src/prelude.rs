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
pub use crate::model::{ApplyActions, Model, WriteAction};
pub use storage_core::{
    backend::{
        AsyncBackend, AsyncBackendImpl, Backend, BackendImpl, BaseBackend, Data, ReadOps, TxRo,
        TxRw, WriteOps,
    },
    DbDesc, DbMapCount, DbMapDesc, DbMapId, DbMapsData,
};
pub use utils::{sync, thread};

pub use std::{mem::drop, sync::Arc};

/// A function to construct a backend
pub trait BackendFn<B>: Fn() -> B + Send + Sync + 'static {}
impl<B, F: Fn() -> B + Send + Sync + 'static> BackendFn<B> for F {}

/// A couple of DB map ID constants
pub const MAPID: (DbMapId, DbMapId) = (DbMapId::new(0), DbMapId::new(1));

/// Sample database description with `n` maps
pub fn desc(n: usize) -> DbDesc {
    storage_core::types::construct::db_desc((0..n).map(|i| DbMapDesc::new(format!("map_{i:02}"))))
}

/// Run tests with backend using proptest
pub fn using_proptest<B: BaseBackend, F: BackendFn<B>, S: proptest::prelude::Strategy>(
    source_file: &'static str,
    backend_fn: impl std::ops::Deref<Target = F>,
    strategy: S,
    test: impl Fn(B, S::Value),
) {
    let config = {
        let mut config = proptest::prelude::ProptestConfig::with_source_file(source_file);
        // Decrease the number of test cases. By default, this is 256 / 8 = 64.
        config.cases /= 8;
        config
    };
    let mut runner = proptest::test_runner::TestRunner::new(config);
    let result = runner.run(&strategy, |val| {
        test(backend_fn(), val);
        Ok(())
    });
    result.unwrap_or_else(|e| panic!("{}{}", &e, &runner))
}

/// Test helper function not exported with the prelude
pub mod support {
    use super::*;
    use libtest_mimic::Trial;

    /// Create the test list
    pub fn create_tests<B: Backend + 'static, F: BackendFn<B>>(
        backend_fn: Arc<F>,
        tests: impl IntoIterator<Item = (&'static str, fn(Arc<F>))>,
    ) -> impl Iterator<Item = Trial> {
        tests.into_iter().map(move |(name, test)| {
            let backend_fn = Arc::clone(&backend_fn);
            let test_fn = move || {
                utils::concurrency::model(move || test(backend_fn.clone()));
                Ok(())
            };
            Trial::test(name, test_fn)
        })
    }

    pub fn async_create_tests<B: AsyncBackend + 'static, F: BackendFn<B>>(
        backend_fn: Arc<F>,
        tests: impl IntoIterator<Item = (&'static str, fn(Arc<F>))>,
    ) -> impl Iterator<Item = Trial> {
        tests.into_iter().map(move |(name, test)| {
            let backend_fn = Arc::clone(&backend_fn);
            let test_fn = move || {
                utils::concurrency::model(move || test(backend_fn.clone()));
                Ok(())
            };
            Trial::test(name, test_fn)
        })
    }
}

macro_rules! tests {
    ($($name:path),* $(,)?) => {
        pub fn tests<B: $crate::prelude::Backend + 'static, F: $crate::prelude::BackendFn<B>>(
            backend_fn: Arc<F>,
        ) -> impl std::iter::Iterator<Item = libtest_mimic::Trial> {
            $crate::prelude::support::create_tests(backend_fn, [
                $((concat!(module_path!(), "::", stringify!($name)), $name as fn(Arc<F>)),)*
            ])
        }
    }
}

macro_rules! async_tests {
    ($($name:path),* $(,)?) => {
        pub fn async_tests<B: $crate::prelude::AsyncBackend + 'static, F: $crate::prelude::BackendFn<B>>(
            backend_fn: Arc<F>,
        ) -> impl std::iter::Iterator<Item = libtest_mimic::Trial> {
            $crate::prelude::support::async_create_tests(backend_fn, [
                $((concat!(module_path!(), "::", stringify!($name)), $name as fn(Arc<F>)),)*
            ])
        }
    }
}
