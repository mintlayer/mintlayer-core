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

use std::sync::Mutex;

use chainstate_storage::{BlockchainStorage, TransactionRw, Transactional};
use chainstate_types::storage_result;
use logging::log;
use test_utils::random::{Rng, Seed, TestRng};
use utils::atomics::AcqRelAtomicU32;

mod read;
mod write;

#[derive(Debug, Clone)]
pub struct FailureParams {
    pub failure_probability: f32,
    pub max_failures: u32,
}

impl FailureParams {
    // Set the default probability of failure for affected operations to 5%. Also limit the max
    // number of spurious failures to 4, since that is the maximum amount the system is designed
    // to handle by default, making max 10 attempts before giving up.
    pub const FAILING: Self = Self::new_unchecked(0.05, 4);

    // Reliable storage can be achieved by either setting the failure probability to zero or by
    // limiting the max number of spurious errors to zero. Here, we do both just in case.
    pub const RELIABLE: Self = Self::new_unchecked(0.00, 0);

    const fn new_unchecked(failure_probability: f32, max_failures: u32) -> Self {
        Self {
            failure_probability,
            max_failures,
        }
    }

    pub fn new(failure_probability: f32, max_failures: u32) -> Self {
        assert!(
            (0.0..=1.0).contains(&failure_probability),
            "{failure_probability} not a probability"
        );
        Self::new_unchecked(failure_probability, max_failures)
    }
}

/// Chainstate storage that occasionally fails to resize storage map.
#[derive(Debug)]
pub struct FailingStorage<S> {
    inner: S,
    failures: AcqRelAtomicU32,
    params: FailureParams,
    rng: Mutex<TestRng>,
}

impl<S> FailingStorage<S> {
    pub fn new_failing(inner: S, seed: Seed) -> Self {
        Self::from_storage_with_params(inner, seed, FailureParams::FAILING)
    }

    pub fn new_reliable(inner: S) -> Self {
        // Note: Random seed is irrelevant if no failures are generated
        Self::from_storage_with_params(inner, Seed(0), FailureParams::RELIABLE)
    }

    pub fn from_storage_with_params(inner: S, seed: Seed, params: FailureParams) -> Self {
        Self {
            inner,
            params,
            failures: AcqRelAtomicU32::new(0).into(),
            rng: Mutex::new(TestRng::new(seed)),
        }
    }

    pub fn from_storage_reliable(storage: S) -> Self {
        Self::from_storage_with_params(storage, Seed(0), FailureParams::RELIABLE)
    }

    pub fn set_failures(&mut self, params: FailureParams, seed: Seed) {
        self.reseed(seed);
        self.params = params;
    }

    pub fn reseed(&mut self, seed: Seed) {
        *self.rng.get_mut().unwrap() = TestRng::new(seed);
    }

    pub fn reset_failure_counter(&mut self) {
        self.failures.store(0);
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl FailingStorage<chainstate_storage::inmemory::Store> {
    pub fn new_empty() -> chainstate_storage::Result<Self> {
        chainstate_storage::inmemory::Store::new_empty().map(Self::new_reliable)
    }
}

impl<S: Clone> Clone for FailingStorage<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            failures: AcqRelAtomicU32::new(self.failures.load()),
            params: self.params.clone(),
            rng: Mutex::new(self.rng.lock().unwrap().clone()),
        }
    }
}

impl<S> From<S> for FailingStorage<S> {
    fn from(storage: S) -> Self {
        Self::from_storage_reliable(storage)
    }
}

impl<S: BlockchainStorage> BlockchainStorage for FailingStorage<S> {}

impl<'t, S: Transactional<'t>> Transactional<'t> for FailingStorage<S> {
    type TransactionRo = S::TransactionRo;

    type TransactionRw = FailingStorageTxRw<'t, S::TransactionRw>;

    fn transaction_ro<'s: 't>(&'s self) -> chainstate_storage::Result<Self::TransactionRo> {
        // For now, we do not consider failing read operations
        self.inner.transaction_ro()
    }

    fn transaction_rw<'s: 't>(
        &'s self,
        size: Option<usize>,
    ) -> chainstate_storage::Result<Self::TransactionRw> {
        Ok(FailingStorageTxRw {
            inner: self.inner.transaction_rw(size)?,
            params: &self.params,
            failures: &self.failures,
            rng: TestRng::random(&mut *self.rng.lock().unwrap()),
        })
    }
}

pub struct FailingStorageTxRw<'a, T> {
    inner: T,
    params: &'a FailureParams,
    failures: &'a AcqRelAtomicU32,
    rng: TestRng,
}

impl<T> FailingStorageTxRw<'_, T> {
    fn spurious_failure<E: std::fmt::Debug>(&mut self, err: E) -> Result<(), E> {
        if self.rng.gen_range(0.0_f32..1.0) < self.params.failure_probability {
            let prior_fails = self.failures.fetch_add(1);
            let curr_fails = prior_fails + 1;
            let max_fails = self.params.max_failures;
            if prior_fails < self.params.max_failures {
                log::debug!("Spuriously emitting error ({curr_fails}/{max_fails}) {err:?}");
                return Err(err);
            } else {
                let _ = self.failures.fetch_min(self.params.max_failures);
            }
        }

        Ok(())
    }

    fn spurious_map_full_failure(&mut self) -> storage_result::Result<()> {
        let err = storage_core::Error::from(storage_core::error::Recoverable::MemMapFull);
        self.spurious_failure(err.into())
    }
}

impl<T: TransactionRw> TransactionRw for FailingStorageTxRw<'_, T> {
    fn abort(self) -> chainstate_storage::Result<()> {
        self.inner.abort()
    }

    fn commit(self) -> chainstate_storage::Result<()> {
        self.inner.commit()
    }
}
