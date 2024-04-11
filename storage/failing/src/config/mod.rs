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

use std::collections::BTreeMap;

use storage_core::{error::Recoverable as StorageError, DbMapId};
use test_utils::random::{IteratorRandom, Rng};
use utils::ensure;

pub mod builder;

#[enumflags2::bitflags]
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ErrorToEmit {
    TransactionFailed,
    TemporarilyUnavailable,
    MemMapFull,
}

impl ErrorToEmit {
    fn from_err(err: StorageError) -> Self {
        err.try_into().expect("Unsupported")
    }
}

#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
enum UnsupportedError {
    #[error("The emission of the error {0:?} is not supported by the failing storage layer")]
    Unsupported(StorageError),
}

impl TryFrom<StorageError> for ErrorToEmit {
    type Error = UnsupportedError;

    fn try_from(value: StorageError) -> Result<Self, Self::Error> {
        match value {
            StorageError::TransactionFailed => Ok(Self::TransactionFailed),
            StorageError::TemporarilyUnavailable => Ok(Self::TemporarilyUnavailable),
            StorageError::MemMapFull => Ok(Self::MemMapFull),
            e @ (StorageError::DbInit | StorageError::Io(_, _)) => {
                Err(UnsupportedError::Unsupported(e))
            }
        }
    }
}

impl From<ErrorToEmit> for StorageError {
    fn from(value: ErrorToEmit) -> Self {
        match value {
            ErrorToEmit::TransactionFailed => StorageError::TransactionFailed,
            ErrorToEmit::TemporarilyUnavailable => StorageError::TemporarilyUnavailable,
            ErrorToEmit::MemMapFull => StorageError::MemMapFull,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ErrorSet(enumflags2::BitFlags<ErrorToEmit>);

impl ErrorSet {
    pub const ALL: Self = Self(enumflags2::BitFlags::<ErrorToEmit>::ALL);

    /// Always generate this particular error
    pub fn single(err: StorageError) -> Self {
        Self(ErrorToEmit::from_err(err).into())
    }

    pub fn generate(&self, rng: &mut impl Rng) -> Option<StorageError> {
        self.0.iter().choose(rng).map(StorageError::from)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromIterator<StorageError> for ErrorSet {
    fn from_iter<T: IntoIterator<Item = StorageError>>(iter: T) -> Self {
        Self(iter.into_iter().map(ErrorToEmit::from_err).collect())
    }
}

impl From<StorageError> for ErrorSet {
    fn from(err: StorageError) -> Self {
        Self::single(err)
    }
}

#[derive(Debug, Clone)]
pub struct ErrorGeneration {
    probability: f32,
    errors: ErrorSet,
}

impl ErrorGeneration {
    pub const INACTIVE: Self = Self::new_internal(0.0, ErrorSet::ALL);

    pub fn new(probability: f32, errors: impl Into<ErrorSet>) -> Self {
        let errors = errors.into();
        assert!(
            (0.0..=1.0_f32).contains(&probability),
            "Invalid probability {probability}, must be between 0.0 and 1.0",
        );
        assert!(
            probability == 0.0 || !errors.is_empty(),
            "Non-zero failure probability but error set is empty",
        );

        Self::new_internal(probability, errors)
    }

    const fn new_internal(probability: f32, errors: ErrorSet) -> Self {
        Self {
            probability,
            errors,
        }
    }

    pub fn generate(&self, rng: &mut impl Rng) -> Option<StorageError> {
        ensure!(rng.gen_bool(self.probability.into()));
        self.errors.generate(rng)
    }
}

#[derive(Debug, Clone)]
pub struct FailureConfig {
    max_failures_total: u32,
    max_failures_per_transaction: u32,
    default_error_generation_write: ErrorGeneration,
    default_error_generation_del: ErrorGeneration,
    error_generation_commit: ErrorGeneration,
    error_generation_start_rw_tx: ErrorGeneration,
    error_generation_write: BTreeMap<DbMapId, ErrorGeneration>,
    error_generation_del: BTreeMap<DbMapId, ErrorGeneration>,
}

impl FailureConfig {
    /// Inactive failure generation with given limits. Operation failure probabilities have to be
    /// configured in order to actually start generating errors.
    fn inactive(max_failures_total: u32, max_failures_per_transaction: u32) -> Self {
        Self {
            max_failures_total,
            max_failures_per_transaction,
            default_error_generation_write: ErrorGeneration::INACTIVE,
            default_error_generation_del: ErrorGeneration::INACTIVE,
            error_generation_commit: ErrorGeneration::INACTIVE,
            error_generation_start_rw_tx: ErrorGeneration::INACTIVE,
            error_generation_write: BTreeMap::new(),
            error_generation_del: BTreeMap::new(),
        }
    }

    /// Reliable storage
    pub fn reliable() -> Self {
        Self::inactive(0, 0)
    }

    pub fn builder<Sch>() -> builder::Builder<Sch> {
        builder::Builder::new(Self::inactive(1_u32 << 31, 5))
    }

    pub fn error_generation_for_write(&self, map_id: DbMapId) -> &ErrorGeneration {
        let default = &self.default_error_generation_write;
        self.error_generation_write.get(&map_id).unwrap_or(default)
    }

    pub fn error_generation_for_del(&self, map_id: DbMapId) -> &ErrorGeneration {
        let default = &self.default_error_generation_del;
        self.error_generation_del.get(&map_id).unwrap_or(default)
    }

    pub fn error_generation_for_commit(&self) -> &ErrorGeneration {
        &self.error_generation_commit
    }

    pub fn error_generation_for_start_rw_tx(&self) -> &ErrorGeneration {
        &self.error_generation_start_rw_tx
    }

    pub fn max_failures_per_transaction(&self) -> u32 {
        self.max_failures_per_transaction
    }

    pub fn max_failures_total(&self) -> u32 {
        self.max_failures_total
    }
}
