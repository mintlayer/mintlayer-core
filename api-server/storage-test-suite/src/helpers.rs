use std::sync::Arc;

use api_server_common::storage::storage_api::ApiServerStorage;
use libtest_mimic::{Failed, Trial};
use test_utils::random::Seed;

pub fn make_trial<
    S: ApiServerStorage,
    F: Fn() -> S + Send + Sync + 'static,
    T: FnOnce(Arc<F>, Box<dyn Fn() -> Seed + Send>) -> Result<(), Failed> + Send + 'static,
>(
    name: &'static str,
    test: T,
    storage_maker: Arc<F>,
) -> libtest_mimic::Trial {
    let make_seed: Box<dyn Fn() -> Seed + Send> = Box::new(|| Seed::from_entropy_and_print(name));
    Trial::test(name, move || test(storage_maker, make_seed))
}

#[macro_export]
macro_rules! make_test {
    ($name:ident, $storage_maker:expr) => {
        make_trial(stringify!($name), $name, $storage_maker)
    };
}
