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

use crate::error::DnsServerError;

pub trait DnsServerStorageRead {
    fn get_addresses(&self) -> Result<Vec<String>, DnsServerError>;
}

pub trait DnsServerStorageWrite {
    fn add_address(&mut self, address: &str) -> Result<(), DnsServerError>;

    fn del_address(&mut self, address: &str) -> Result<(), DnsServerError>;
}

pub trait DnsServerTransactionRo: DnsServerStorageRead {
    fn close(self);
}

pub trait DnsServerTransactionRw: DnsServerStorageWrite {
    fn abort(self);

    fn commit(self) -> Result<(), DnsServerError>;
}

/// Support for transactions over blockchain storage
pub trait DnsServerTransactional<'t> {
    /// Associated read-only transaction type.
    type TransactionRo: DnsServerTransactionRo + 't;

    /// Associated read-write transaction type.
    type TransactionRw: DnsServerTransactionRw + 't;

    /// Start a read-only transaction.
    fn transaction_ro<'s: 't>(&'s self) -> Result<Self::TransactionRo, DnsServerError>;

    /// Start a read-write transaction.
    fn transaction_rw<'s: 't>(&'s self) -> Result<Self::TransactionRw, DnsServerError>;
}

pub trait DnsServerStorage: for<'tx> DnsServerTransactional<'tx> + Send {}
