// Copyright (c) 2021-2023 RBB S.r.l
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

use utils::try_as::TryAsRef;

use serialization::{Decode, Encode};

#[derive(Debug, derive_more::Display, Clone, Copy, Encode, Decode, Eq, PartialEq)]
pub struct StorageVersion(u32);

impl StorageVersion {
    pub const fn new(val: u32) -> Self {
        Self(val)
    }
}

pub trait TransactionRo {
    fn close(self);
}

pub trait TransactionRw {
    fn abort(self);

    fn commit(self) -> Result<(), storage::Error>;
}

pub trait Transactional<'t> {
    /// Associated read-only transaction type.
    type TransactionRo: TransactionRo + 't;

    /// Associated read-write transaction type.
    type TransactionRw: TransactionRw + 't;

    /// Start a read-only transaction.
    fn transaction_ro<'s: 't>(&'s self) -> Result<Self::TransactionRo, storage::Error>;

    /// Start a read-write transaction.
    fn transaction_rw<'s: 't>(&'s self) -> Result<Self::TransactionRw, storage::Error>;
}

const MAX_RECOVERABLE_ERROR_RETRY_COUNT: u32 = 3;

/// Try updating the storage, gracefully handle recoverable errors.
pub fn update_db<'t, S, F, E>(storage: &'t S, f: F) -> Result<(), E>
where
    S: Transactional<'t> + Send,
    F: Fn(&mut <S as Transactional<'t>>::TransactionRw) -> Result<(), E>,
    E: std::error::Error + From<storage::Error> + TryAsRef<storage::Error>,
{
    let mut recoverable_errors = 0;
    loop {
        let res = || -> Result<(), E> {
            let mut tx = storage.transaction_rw()?;
            f(&mut tx)?;
            Ok(tx.commit()?)
        }();

        match res {
            Ok(()) => return Ok(()),
            Err(err) => {
                let storage_err = err.try_as_ref();
                if storage_err.is_some_and(|e| e.is_recoverable()) {
                    recoverable_errors += 1;
                    if recoverable_errors < MAX_RECOVERABLE_ERROR_RETRY_COUNT {
                        continue;
                    }
                }
                return Err(err);
            }
        }
    }
}
