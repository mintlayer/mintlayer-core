use api_server_common::storage::impls::in_memory::transactional::TransactionalApiServerInMemoryStorage;
use common::chain::{config::create_unit_test_config, ChainConfig};

#[must_use]
pub fn make_in_memory_storage(chain_config: &ChainConfig) -> TransactionalApiServerInMemoryStorage {
    TransactionalApiServerInMemoryStorage::new(chain_config)
}

fn main() {
    let storage_maker = || make_in_memory_storage(&create_unit_test_config());
    let result = api_server_backend_test_suite::run(storage_maker);

    result.exit()
}
