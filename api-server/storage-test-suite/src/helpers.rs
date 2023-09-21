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

use std::{future::Future, sync::Arc};

use api_server_common::storage::storage_api::ApiServerStorage;
use futures::executor::block_on;
use libtest_mimic::{Failed, Trial};
use test_utils::random::Seed;

pub fn make_trial<
	C: 'static,
    S: ApiServerStorage + Send + Sync + 'static,
    F: Fn() -> (S, C) + Send + Sync + 'static,
    Fut: Future<Output = Result<(), Failed>> + 'static,
    T: FnOnce(Arc<F>, Box<dyn Fn() -> Seed + Send>) -> Fut + Send + 'static,
>(
    name: &'static str,
    test: T,
    storage_maker: Arc<F>,
) -> libtest_mimic::Trial {
    let make_seed: Box<dyn Fn() -> Seed + Send> = Box::new(|| Seed::from_entropy_and_print(name));
    Trial::test(name, move || {
        block_on(async { test(storage_maker, make_seed).await })
    })
}

#[macro_export]
macro_rules! make_test {
    ($name:ident, $storage_maker:expr) => {
	tokio::runtime::Runtime::new().unwrap().block_on(async {
            make_trial(stringify!($name), $name, $storage_maker)
	})
    };
}
