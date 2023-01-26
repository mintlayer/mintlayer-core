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
    fn get_known_addresses(&self) -> crate::Result<Vec<String>>;

    fn get_banned_addresses(&self) -> crate::Result<Vec<(String, Duration)>>;
}

pub trait PeerDbStorageWrite {
    fn add_known_address(&mut self, address: &str) -> crate::Result<()>;

    fn del_known_address(&mut self, address: &str) -> crate::Result<()>;

    fn add_banned_address(&mut self, address: &str, duration: Duration) -> crate::Result<()>;

    fn del_banned_address(&mut self, address: &str) -> crate::Result<()>;
}

pub trait PeerDbTransactionRo: PeerDbStorageRead {
    fn close(self);
}

pub trait PeerDbTransactionRw: PeerDbStorageWrite {
    fn abort(self);

    fn commit(self) -> crate::Result<()>;
}

/// Support for transactions over blockchain storage
pub trait PeerDbTransactional<'t> {
    /// Associated read-only transaction type.
    type TransactionRo: PeerDbTransactionRo + 't;

    /// Associated read-write transaction type.
    type TransactionRw: PeerDbTransactionRw + 't;

    /// Start a read-only transaction.
    fn transaction_ro<'s: 't>(&'s self) -> crate::Result<Self::TransactionRo>;

    /// Start a read-write transaction.
    fn transaction_rw<'s: 't>(&'s self) -> crate::Result<Self::TransactionRw>;
}

pub trait PeerDbStorage: for<'tx> PeerDbTransactional<'tx> + Send {}
