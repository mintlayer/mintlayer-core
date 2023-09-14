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
