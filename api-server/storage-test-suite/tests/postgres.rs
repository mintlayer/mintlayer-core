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

mod containers;

use std::sync::Arc;

use api_server_common::storage::{
    impls::postgres::TransactionalApiServerPostgresStorage, storage_api::ApiServerStorage,
};
use common::chain::{config::create_unit_test_config, ChainConfig};
use containers::with_container::ApiServerStorageWithContainer;

#[must_use]
async fn make_postgres_storage(chain_config: Arc<ChainConfig>) -> impl ApiServerStorage {
    let container = containers::podman::Container::PostgresFromDockerHub;

    let podman = containers::podman::Podman::new("MintlayerPostgresTest", container)
        .with_env("POSTGRES_PASSWORD", "mysecretpassword")
        .with_port_mapping(None, 5432);

    podman.run();

    let host_port = podman.get_port_mapping(5432).unwrap();

    println!("Port mapping: {}", host_port);

    let storage = TransactionalApiServerPostgresStorage::new(
        "127.0.0.1",
        host_port,
        "postgres",
        None,
        None,
        4,
        &chain_config,
    )
    .await
    .unwrap();

    ApiServerStorageWithContainer::new(storage, podman)
}

fn main() {
    let storage_maker = || make_postgres_storage(Arc::new(create_unit_test_config()));
    let result = api_server_backend_test_suite::run(storage_maker);

    result.exit()
}
