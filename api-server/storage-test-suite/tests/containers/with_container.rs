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

use api_server_backend_test_suite::podman::Podman;
use api_server_common::storage::storage_api::{
    ApiServerStorage, ApiServerStorageError, Transactional,
};

pub struct ApiServerStorageWithContainer<S: ApiServerStorage> {
    storage: S,
    _container: Podman,
}

impl<S: ApiServerStorage> ApiServerStorageWithContainer<S> {
    pub fn new(storage: S, container: Podman) -> ApiServerStorageWithContainer<S> {
        Self {
            storage,
            _container: container,
        }
    }
}

#[async_trait::async_trait]
impl<'tx, S: ApiServerStorage> Transactional<'tx> for ApiServerStorageWithContainer<S> {
    type TransactionRo = <S as Transactional<'tx>>::TransactionRo;

    type TransactionRw = <S as Transactional<'tx>>::TransactionRw;
    async fn transaction_ro<'db: 'tx>(
        &'db self,
    ) -> Result<Self::TransactionRo, ApiServerStorageError> {
        self.storage.transaction_ro().await
    }

    async fn transaction_rw<'db: 'tx>(
        &'db mut self,
    ) -> Result<Self::TransactionRw, ApiServerStorageError> {
        self.storage.transaction_rw().await
    }
}

impl<S: ApiServerStorage> ApiServerStorage for ApiServerStorageWithContainer<S> {}
