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
pub fn update_db<'t, S, F>(storage: &'t S, f: F) -> Result<(), storage::Error>
where
    S: Transactional<'t> + Send,
    F: Fn(&mut <S as Transactional<'t>>::TransactionRw) -> Result<(), storage::Error>,
{
    let mut recoverable_errors = 0;
    loop {
        let res = || -> Result<(), storage::Error> {
            let mut tx = storage.transaction_rw()?;
            f(&mut tx)?;
            tx.commit()
        }();

        match res {
            Ok(()) => return Ok(()),
            err @ Err(storage::Error::Recoverable(_)) => {
                recoverable_errors += 1;
                if recoverable_errors >= MAX_RECOVERABLE_ERROR_RETRY_COUNT {
                    return err;
                }
            }
            err @ Err(storage::Error::Fatal(_)) => return err,
        }
    }
}
