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

use std::sync::Arc;

use api_server_common::storage::{
    impls::in_memory::transactional::TransactionalApiServerInMemoryStorage,
    storage_api::ApiServerStorage,
};
use common::chain::{config::create_unit_test_config, ChainConfig};
use utils::rust_backtrace;

#[must_use]
#[allow(clippy::unused_async)]
async fn make_in_memory_storage(chain_config: Arc<ChainConfig>) -> impl ApiServerStorage {
    TransactionalApiServerInMemoryStorage::new(&chain_config)
}

fn main() {
    rust_backtrace::enable();

    let storage_maker = || make_in_memory_storage(Arc::new(create_unit_test_config()));
    let result = api_server_backend_test_suite::run(storage_maker);

    result.exit()
}
