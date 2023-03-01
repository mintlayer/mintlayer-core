// Copyright (c) 2023 RBB S.r.l
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

use std::time::Duration;

pub trait PeerDbStorageRead {
    fn get_version(&self) -> Result<Option<u32>, storage::Error>;

    fn get_known_addresses(&self) -> Result<Vec<String>, storage::Error>;

    fn get_banned_addresses(&self) -> Result<Vec<(String, Duration)>, storage::Error>;
}

pub trait PeerDbStorageWrite {
    fn set_version(&mut self, version: u32) -> Result<(), storage::Error>;

    fn add_known_address(&mut self, address: &str) -> Result<(), storage::Error>;

    fn del_known_address(&mut self, address: &str) -> Result<(), storage::Error>;

    fn add_banned_address(
        &mut self,
        address: &str,
        duration: Duration,
    ) -> Result<(), storage::Error>;

    fn del_banned_address(&mut self, address: &str) -> Result<(), storage::Error>;
}

pub trait PeerDbTransactionRo: PeerDbStorageRead {
    fn close(self);
}

pub trait PeerDbTransactionRw: PeerDbStorageWrite {
    fn abort(self);

    fn commit(self) -> Result<(), storage::Error>;
}

/// Support for transactions over blockchain storage
pub trait PeerDbTransactional<'t> {
    /// Associated read-only transaction type.
    type TransactionRo: PeerDbTransactionRo + 't;

    /// Associated read-write transaction type.
    type TransactionRw: PeerDbTransactionRw + 't;

    /// Start a read-only transaction.
    fn transaction_ro<'s: 't>(&'s self) -> Result<Self::TransactionRo, storage::Error>;

    /// Start a read-write transaction.
    fn transaction_rw<'s: 't>(&'s self) -> Result<Self::TransactionRw, storage::Error>;
}

pub trait PeerDbStorage: for<'tx> PeerDbTransactional<'tx> + Send {}

const MAX_RECOVERABLE_ERROR_RETRY_COUNT: u32 = 3;

/// Try update storage, gracefully handle recoverable errors
pub fn update_db<S, F>(storage: &S, f: F) -> Result<(), storage::Error>
where
    S: PeerDbStorage,
    F: Fn(&mut <S as PeerDbTransactional<'_>>::TransactionRw) -> Result<(), storage::Error>,
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
