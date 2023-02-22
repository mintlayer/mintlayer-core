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

pub trait DnsServerStorageRead {
    fn get_version(&self) -> Result<Option<u32>, storage::Error>;

    fn get_addresses(&self) -> Result<Vec<String>, storage::Error>;
}

pub trait DnsServerStorageWrite {
    fn set_version(&mut self, version: u32) -> Result<(), storage::Error>;

    fn add_address(&mut self, address: &str) -> Result<(), storage::Error>;

    fn del_address(&mut self, address: &str) -> Result<(), storage::Error>;
}

pub trait DnsServerTransactionRo: DnsServerStorageRead {
    fn close(self);
}

pub trait DnsServerTransactionRw: DnsServerStorageWrite {
    fn abort(self);

    fn commit(self) -> Result<(), storage::Error>;
}

/// Support for transactions over blockchain storage
pub trait DnsServerTransactional<'t> {
    /// Associated read-only transaction type.
    type TransactionRo: DnsServerTransactionRo + 't;

    /// Associated read-write transaction type.
    type TransactionRw: DnsServerTransactionRw + 't;

    /// Start a read-only transaction.
    fn transaction_ro<'s: 't>(&'s self) -> Result<Self::TransactionRo, storage::Error>;

    /// Start a read-write transaction.
    fn transaction_rw<'s: 't>(&'s self) -> Result<Self::TransactionRw, storage::Error>;
}

pub trait DnsServerStorage: for<'tx> DnsServerTransactional<'tx> + Send {}

const MAX_RECOVERABLE_ERROR_RETRY_COUNT: u32 = 3;

/// Try update storage, gracefully handle recoverable errors
pub fn update_db<S, F>(storage: &S, f: F) -> Result<(), storage::Error>
where
    S: DnsServerStorage,
    F: Fn(&mut <S as DnsServerTransactional<'_>>::TransactionRw) -> Result<(), storage::Error>,
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
            Err(storage::Error::Recoverable(e)) => {
                recoverable_errors += 1;
                if recoverable_errors >= MAX_RECOVERABLE_ERROR_RETRY_COUNT {
                    return Err(storage::Error::Recoverable(e));
                }
            }
            Err(storage::Error::Fatal(e)) => return Err(storage::Error::Fatal(e)),
        }
    }
}
