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

// TODO: uncomment when the container stuff is ready.

use api_server_common::storage::{
    impls::postgres::TransactionalApiServerPostgresStorage, storage_api::ApiServerStorage,
};
use common::chain::{config::create_unit_test_config, ChainConfig};
use tokio::runtime::Runtime;

use testcontainers::{clients::Cli, images::postgres::Postgres};

#[must_use]
fn make_postgres_storage(chain_config: &ChainConfig) -> impl ApiServerStorage {
    let docker = Cli::default();
    let image = Postgres::default();
    let container = docker.run(image);
    
    container.start();

    Runtime::new().unwrap().block_on(async {
        TransactionalApiServerPostgresStorage::new(
            "localhost",
            container.get_host_port_ipv4(5432),
            "postgres",
            4,
            chain_config,
        )
        .await
        .unwrap()
    })
}

// TODO: Make sure to guard this with some feature to prevent running these tests by default
// TODO

fn main() {
    let storage_maker = || make_postgres_storage(&create_unit_test_config());
    let result = api_server_backend_test_suite::run(storage_maker);

    result.exit()
}
