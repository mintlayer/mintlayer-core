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

use storage::schema::Schema;

use super::{TransactionRo, TransactionRw, Transactional};

pub struct StorageImpl<B: storage::SharedBackend, Sch: Schema>(storage::Storage<B, Sch>);

impl<B: storage::SharedBackend, Sch: Schema> StorageImpl<B, Sch> {
    pub fn new(storage: B) -> crate::Result<Self> {
        let store = storage::Storage::<_, Sch>::new(storage)?;
        Ok(Self(store))
    }
}

impl<'tx, B: storage::SharedBackend + 'tx, Sch: Schema> Transactional<'tx> for StorageImpl<B, Sch> {
    type TransactionRo = StorageTxRo<'tx, B, Sch>;
    type TransactionRw = StorageTxRw<'tx, B, Sch>;

    fn transaction_ro<'st: 'tx>(&'st self) -> Result<Self::TransactionRo, storage::Error> {
        self.0.transaction_ro().map(StorageTxRo)
    }

    fn transaction_rw<'st: 'tx>(&'st self) -> Result<Self::TransactionRw, storage::Error> {
        <storage::Storage<_, _> as storage::StorageSharedWrite<_, _>>::transaction_rw(&self.0, None)
            .map(StorageTxRw)
    }
}

pub struct StorageTxRo<'st, B: storage::SharedBackend, Sch: Schema>(
    storage::TransactionRo<'st, B, Sch>,
);

impl<'st, B: storage::SharedBackend, Sch: Schema> StorageTxRo<'st, B, Sch> {
    pub fn storage(&self) -> &storage::TransactionRo<'st, B, Sch> {
        &self.0
    }
}

impl<B: storage::SharedBackend, Sch: Schema> TransactionRo for StorageTxRo<'_, B, Sch> {
    fn close(self) {
        self.0.close()
    }
}

pub struct StorageTxRw<'st, B: storage::SharedBackend, Sch: Schema>(
    storage::TransactionRw<'st, B, Sch>,
);

impl<'st, B: storage::SharedBackend, Sch: Schema> StorageTxRw<'st, B, Sch> {
    pub fn storage(&mut self) -> &mut storage::TransactionRw<'st, B, Sch> {
        &mut self.0
    }
}

impl<B: storage::SharedBackend, Sch: Schema> TransactionRw for StorageTxRw<'_, B, Sch> {
    fn abort(self) {
        self.0.abort()
    }

    fn commit(self) -> Result<(), storage::Error> {
        self.0.commit()
    }
}
