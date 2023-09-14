use std::sync::Arc;

use api_server_common::storage::storage_api::{ApiServerStorage, ApiServerStorageRead};
use libtest_mimic::{Failed, Trial};

pub fn initialization<S: ApiServerStorage, F: Fn() -> S>(
    storage_maker: Arc<F>,
) -> Result<(), Failed> {
    let storage = storage_maker();
    let mut tx = storage.transaction_ro().unwrap();
    assert!(tx.is_initialized().unwrap());
    Ok(())
}

pub fn build_tests<S: ApiServerStorage, F: Fn() -> S + Send + Sync + 'static>(
    storage_maker: Arc<F>,
) -> impl Iterator<Item = libtest_mimic::Trial> {
    vec![Trial::test("initialization", move || initialization(storage_maker))].into_iter()
}
