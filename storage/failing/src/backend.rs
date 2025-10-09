// Copyright (c) 2024 RBB S.r.l
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

use std::{
    borrow::Cow,
    sync::{Arc, Mutex},
};

use storage_core::{backend, Data, DbMapId};
use test_utils::random::{Rng, Seed, TestRng};
use utils::{atomics::AcqRelAtomicU32, shallow_clone::ShallowClone};

use crate::{ErrorGeneration, FailureConfig};

pub struct Failing<B> {
    inner: B,
    config: FailureConfig,
    seed: Seed,
}

impl<B> Failing<B> {
    /// New failing storage backend adaptor.
    pub fn new(inner: B, config: FailureConfig, seed: Seed) -> Self {
        Self {
            inner,
            config,
            seed,
        }
    }

    /// New reliable storage backend adaptor.
    pub fn reliable(inner: B) -> Self {
        Self::new(inner, FailureConfig::reliable(), Seed(0))
    }
}

impl<B: Default> Default for Failing<B> {
    fn default() -> Self {
        Self::reliable(B::default())
    }
}

impl<B: backend::Backend> backend::Backend for Failing<B> {
    type Impl = FailingImpl<B::Impl>;

    fn open(self, desc: storage_core::DbDesc) -> storage_core::Result<Self::Impl> {
        let Self {
            inner,
            config,
            seed,
        } = self;

        Ok(FailingImpl::new(inner.open(desc)?, config, seed))
    }
}

impl<B: backend::SharedBackend> backend::SharedBackend for Failing<B> {
    type ImplHelper = FailingImpl<B::Impl>;
}

pub struct FailingImpl<T> {
    inner: T,
    config: Arc<FailureConfig>,
    rng: Mutex<TestRng>,
    total_failures: Arc<AcqRelAtomicU32>,
}

impl<T> FailingImpl<T> {
    fn new(inner: T, config: FailureConfig, seed: Seed) -> Self {
        Self {
            inner,
            config: Arc::new(config),
            rng: TestRng::new(seed).into(),
            total_failures: AcqRelAtomicU32::new(0).into(),
        }
    }

    fn make_rng(&self) -> TestRng {
        Self::make_rng_impl(&self.rng)
    }

    fn make_rng_impl(rng: &Mutex<TestRng>) -> TestRng {
        TestRng::new(Seed(rng.lock().expect("lock poisoned").gen()))
    }

    fn make_rw_tx_state<'a>(
        config: &'a FailureConfig,
        rng: &Mutex<TestRng>,
        total_failures: &'a AcqRelAtomicU32,
    ) -> RwTxState<'a> {
        RwTxState {
            config,
            rng: Self::make_rng_impl(rng),
            total_failures,
            transaction_failures: 0,
        }
    }
}

impl<T: Clone> Clone for FailingImpl<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            config: self.config.clone(),
            rng: self.make_rng().into(),
            total_failures: self.total_failures.clone(),
        }
    }
}

impl<T: ShallowClone> ShallowClone for FailingImpl<T> {
    fn shallow_clone(&self) -> Self {
        self.clone()
    }
}

impl<T: backend::BackendImpl> backend::BackendImpl for FailingImpl<T> {
    type TxRo<'a> = T::TxRo<'a>;

    type TxRw<'a> = TxRw<'a, T::TxRw<'a>>;

    fn transaction_ro(&self) -> storage_core::Result<Self::TxRo<'_>> {
        self.inner.transaction_ro()
    }

    fn transaction_rw(&mut self, size: Option<usize>) -> storage_core::Result<Self::TxRw<'_>> {
        let mut state = Self::make_rw_tx_state(&self.config, &self.rng, &self.total_failures);
        state.emit_error(self.config.error_generation_for_start_rw_tx())?;
        let inner = self.inner.transaction_rw(size)?;
        Ok(TxRw { inner, state })
    }
}

impl<T: backend::SharedBackendImpl> backend::SharedBackendImpl for FailingImpl<T> {
    fn transaction_rw(&self, size: Option<usize>) -> storage_core::Result<Self::TxRw<'_>> {
        let mut state = Self::make_rw_tx_state(&self.config, &self.rng, &self.total_failures);
        state.emit_error(self.config.error_generation_for_start_rw_tx())?;
        let inner = self.inner.transaction_rw(size)?;
        Ok(TxRw { inner, state })
    }
}

struct RwTxState<'a> {
    config: &'a FailureConfig,
    rng: TestRng,
    total_failures: &'a AcqRelAtomicU32,
    transaction_failures: u32,
}

impl RwTxState<'_> {
    fn emit_error(&mut self, eg: &ErrorGeneration) -> storage_core::Result<()> {
        if self.transaction_failures < self.config.max_failures_per_transaction() {
            if let Some(err) = eg.generate(&mut self.rng) {
                if self.total_failures.fetch_add(1) < self.config.max_failures_total() {
                    self.transaction_failures += 1;
                    return Err(err.into());
                } else {
                    // Correct the previous fetch_add if we reached the max.
                    self.total_failures.fetch_sub(1);
                }
            }
        }
        Ok(())
    }
}

pub struct TxRw<'a, T> {
    inner: T,
    state: RwTxState<'a>,
}

impl<T: backend::TxRw> backend::TxRw for TxRw<'_, T> {
    fn commit(mut self) -> storage_core::Result<()> {
        self.state.emit_error(self.state.config.error_generation_for_commit())?;
        self.inner.commit()
    }
}

impl<T: backend::ReadOps> backend::ReadOps for TxRw<'_, T> {
    fn get(&self, map_id: DbMapId, key: &[u8]) -> storage_core::Result<Option<Cow<'_, [u8]>>> {
        self.inner.get(map_id, key)
    }

    fn prefix_iter(
        &self,
        map_id: DbMapId,
        prefix: Data,
    ) -> storage_core::Result<impl Iterator<Item = (Data, Data)> + '_> {
        self.inner.prefix_iter(map_id, prefix)
    }

    fn greater_equal_iter(
        &self,
        map_id: DbMapId,
        key: Data,
    ) -> storage_core::Result<impl Iterator<Item = (Data, Data)> + '_> {
        self.inner.greater_equal_iter(map_id, key)
    }
}

impl<T: backend::WriteOps> backend::WriteOps for TxRw<'_, T> {
    fn put(&mut self, map_id: DbMapId, key: Data, val: Data) -> storage_core::Result<()> {
        self.state.emit_error(self.state.config.error_generation_for_write(map_id))?;
        self.inner.put(map_id, key, val)
    }

    fn del(&mut self, map_id: DbMapId, key: &[u8]) -> storage_core::Result<()> {
        self.state.emit_error(self.state.config.error_generation_for_del(map_id))?;
        self.inner.del(map_id, key)
    }
}
