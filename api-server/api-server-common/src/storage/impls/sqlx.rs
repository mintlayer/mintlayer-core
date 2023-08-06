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

use crate::storage::storage_api::ApiStorageError;

pub struct SqlxStorage {
    db_pool: sqlx::AnyConnection,
}

impl SqlxStorage {
    pub fn new(db_pool: sqlx::AnyConnection) -> Result<Self, ApiStorageError> {
        Ok(Self { db_pool })
    }

    pub fn backend_name(&self) -> &str {
        self.db_pool.backend_name()
    }
}
