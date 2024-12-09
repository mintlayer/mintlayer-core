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

use std::{marker::PhantomData, ops::Deref as _};

use utils::shallow_clone::ShallowClone;

// Re-export a bunch of often used items
pub use crate::model::{ApplyActions, Model, WriteAction};
pub use storage_core::{
    backend::{
        Backend, BackendImpl, Data, ReadOps, SharedBackend, SharedBackendImpl, TxRo, TxRw, WriteOps,
    },
    DbDesc, DbMapCount, DbMapDesc, DbMapId, DbMapsData,
};
pub use utils::{sync, thread};

pub use std::{mem::drop, sync::Arc};

pub trait BackendFactory<B>: Send + Sync + 'static {
    fn create(&self) -> B;
}

impl<B, F: Fn() -> B + Send + Sync + 'static> BackendFactory<B> for F {
    fn create(&self) -> B {
        self()
    }
}

impl<B, F: BackendFactory<B>> BackendFactory<B> for Arc<F> {
    fn create(&self) -> B {
        self.deref().create()
    }
}

/// A couple of DB map ID constants
pub const MAPID: (DbMapId, DbMapId) = (DbMapId::new(0), DbMapId::new(1));

/// Sample database description with `n` maps
pub fn desc(n: usize) -> DbDesc {
    storage_core::types::construct::db_desc((0..n).map(|i| DbMapDesc::new(format!("map_{i:02}"))))
}

/// Run tests with backend using proptest
pub fn using_proptest<B: Backend, F: BackendFactory<B>, S: proptest::prelude::Strategy>(
    source_file: &'static str,
    backend_factory: impl std::ops::Deref<Target = F>,
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
        test(backend_factory.create(), val);
        Ok(())
    });
    result.unwrap_or_else(|e| panic!("{}{}", &e, &runner))
}

/// This is only needed so that we can pass None as the second parameter for
/// `storage_backend_test_suite::main` when the backend is not a shared one.
pub struct BogusSharedBackend<B: Backend>(PhantomData<fn() -> B>);

impl<B: Backend> Backend for BogusSharedBackend<B> {
    type Impl = BogusSharedBackendImpl<<B as Backend>::Impl>;

    fn open(self, _desc: DbDesc) -> storage_core::Result<Self::Impl> {
        unimplemented!();
    }
}

impl<B: Backend> SharedBackend for BogusSharedBackend<B> {
    type ImplHelper = BogusSharedBackendImpl<<B as Backend>::Impl>;
}

pub struct BogusSharedBackendImpl<B: BackendImpl>(PhantomData<fn() -> B>);

impl<B: BackendImpl> BackendImpl for BogusSharedBackendImpl<B> {
    type TxRo<'a> = <B as BackendImpl>::TxRo<'a>;
    type TxRw<'a> = <B as BackendImpl>::TxRw<'a>;

    fn transaction_ro(&self) -> storage_core::Result<Self::TxRo<'_>> {
        unimplemented!();
    }

    fn transaction_rw(&mut self, _size: Option<usize>) -> storage_core::Result<Self::TxRw<'_>> {
        unimplemented!();
    }
}

impl<B: BackendImpl> SharedBackendImpl for BogusSharedBackendImpl<B> {
    fn transaction_rw(&self, _size: Option<usize>) -> storage_core::Result<Self::TxRw<'_>> {
        unimplemented!();
    }
}

impl<B: BackendImpl> Clone for BogusSharedBackendImpl<B> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

impl<B: BackendImpl> ShallowClone for BogusSharedBackendImpl<B> {
    fn shallow_clone(&self) -> Self {
        Self(PhantomData)
    }
}

/// Test helper function not exported with the prelude
pub mod support {
    use std::marker::PhantomData;

    use libtest_mimic::Trial;

    use super::*;

    /// Create the test list
    pub fn create_tests<B: Backend + 'static, F: BackendFactory<B>>(
        backend_factory: Arc<F>,
        tests: impl IntoIterator<Item = (&'static str, fn(Arc<F>))>,
    ) -> impl Iterator<Item = Trial> {
        tests.into_iter().map(move |(name, test)| {
            let backend_factory = Arc::clone(&backend_factory);
            let test_fn = move || {
                utils::concurrency::model(move || test(backend_factory.clone()));
                Ok(())
            };
            Trial::test(name, test_fn)
        })
    }

    pub fn create_common_tests_for_shared_backend<
        B: SharedBackend + 'static,
        F: BackendFactory<B>,
    >(
        backend_factory: Arc<F>,
        tests: impl IntoIterator<
            Item = (
                &'static str,
                fn(Arc<SharedBackendWrapperFactory<B, Arc<F>>>),
            ),
        >,
    ) -> impl Iterator<Item = Trial> {
        let backend_factory = Arc::new(SharedBackendWrapperFactory(backend_factory, PhantomData));

        tests.into_iter().map(move |(name, test)| {
            let backend_factory = Arc::clone(&backend_factory);
            let test_fn = move || {
                utils::concurrency::model(move || test(backend_factory.clone()));
                Ok(())
            };
            Trial::test(name, test_fn)
        })
    }

    // A wrapper for a SharedBackend that implements Backend whose impl's transaction_rw invokes
    // SharedBackendImpl::transaction_rw (i.e. via a stared reference to self).
    // This is used to check that, if invoked for a SharedBackend, generic tests work both when
    // the tx is created via BackendImpl::transaction_rw and via SharedBackendImpl::transaction_rw.
    pub struct SharedBackendWrapper<B: SharedBackend>(B);

    impl<B: SharedBackend> Backend for SharedBackendWrapper<B> {
        type Impl = SharedBackendImplWrapper<<B as Backend>::Impl>;

        fn open(self, desc: DbDesc) -> storage_core::Result<Self::Impl> {
            self.0.open(desc).map(SharedBackendImplWrapper)
        }
    }

    pub struct SharedBackendImplWrapper<B: SharedBackendImpl>(B);

    impl<B: SharedBackendImpl> BackendImpl for SharedBackendImplWrapper<B> {
        type TxRo<'a> = <B as BackendImpl>::TxRo<'a>;
        type TxRw<'a> = <B as BackendImpl>::TxRw<'a>;

        fn transaction_ro(&self) -> storage_core::Result<Self::TxRo<'_>> {
            self.0.transaction_ro()
        }

        fn transaction_rw(&mut self, size: Option<usize>) -> storage_core::Result<Self::TxRw<'_>> {
            <B as SharedBackendImpl>::transaction_rw(&self.0, size)
        }
    }

    // This wraps `BackendFactory<B> `and implements `BackendFactory<SharedBackendWrapper<B>>`.
    pub struct SharedBackendWrapperFactory<B: SharedBackend, F: BackendFactory<B>>(
        F,
        PhantomData<fn() -> B>,
    );

    impl<B: SharedBackend + 'static, F: BackendFactory<B>> BackendFactory<SharedBackendWrapper<B>>
        for SharedBackendWrapperFactory<B, F>
    {
        fn create(&self) -> SharedBackendWrapper<B> {
            SharedBackendWrapper(self.0.create())
        }
    }
}

macro_rules! common_tests {
    ($($name:path),* $(,)?) => {
        pub fn common_tests<B: $crate::prelude::Backend + 'static, F: $crate::prelude::BackendFactory<B>>(
            backend_factory: Arc<F>,
        ) -> impl std::iter::Iterator<Item = libtest_mimic::Trial> {
            $crate::prelude::support::create_tests(backend_factory, [
                $((concat!(module_path!(), "::", stringify!($name)), $name as fn(Arc<F>)),)*
            ])
        }

        pub fn common_tests_for_shared_backend<B: $crate::prelude::SharedBackend + 'static, F: $crate::prelude::BackendFactory<B>>(
            backend_factory: Arc<F>,
        ) -> impl std::iter::Iterator<Item = libtest_mimic::Trial> {
            $crate::prelude::support::create_common_tests_for_shared_backend(backend_factory, [
                $((concat!(module_path!(), "::", stringify!($name), "_as_shared_backend"),
                   $name as fn(Arc<$crate::prelude::support::SharedBackendWrapperFactory<B, Arc<F>>>)),)*
            ])
        }
    }
}

macro_rules! shared_backend_tests {
    ($($name:path),* $(,)?) => {
        pub fn tests<B: $crate::prelude::SharedBackend + 'static, F: $crate::prelude::BackendFactory<B>>(
            backend_factory: Arc<F>,
        ) -> impl std::iter::Iterator<Item = libtest_mimic::Trial> {
            $crate::prelude::support::create_tests(backend_factory, [
                $((concat!(module_path!(), "::", stringify!($name)), $name as fn(Arc<F>)),)*
            ])
        }
    }
}
