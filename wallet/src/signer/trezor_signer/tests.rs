// Copyright (c) 2024 RBB S.r.l
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

use rstest::rstest;
use serial_test::serial;

use ::test_utils::random::{make_seedable_rng, Seed};
use logging::log;

use super::{
    test_utils::{find_test_device_and_connect, maybe_spawn_auto_confirmer},
    *,
};

fn trezor_signer(chain_config: Arc<ChainConfig>, _account_index: U31) -> TrezorSigner {
    let mut client = find_test_device_and_connect(false);
    let session_id = client.initialize(None).unwrap().ok().unwrap().session_id().to_vec();

    TrezorSigner::new(chain_config, Arc::new(Mutex::new(client)), session_id)
}

// Note: below, the auto-confirmer thread is spawned via `spawn_thread_aborting_on_panic`;
// this is needed because otherwise if the thread panics, the tests won't be able to progress
// without human intervention.
// This, on the other hand, leads to another problem - if we abort the process right away,
// the rng seed that caused the panic won't be printed. So, in these tests we log the seed
// manually at the start of each test.

#[rstest]
#[trace]
#[serial]
#[case(Seed::from_entropy())]
fn sign_message(#[case] seed: Seed) {
    use crate::signer::tests::generic_tests::test_sign_message;

    log::debug!("sign_message, seed = {seed:?}");

    let _join_guard = maybe_spawn_auto_confirmer();

    let mut rng = make_seedable_rng(seed);

    test_sign_message(&mut rng, trezor_signer);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[serial]
fn sign_transaction_intent(#[case] seed: Seed) {
    use crate::signer::tests::generic_tests::test_sign_transaction_intent;

    log::debug!("sign_transaction_intent, seed = {seed:?}");

    let _join_guard = maybe_spawn_auto_confirmer();

    let mut rng = make_seedable_rng(seed);

    test_sign_transaction_intent(&mut rng, trezor_signer);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[serial]
fn sign_transaction(#[case] seed: Seed) {
    use crate::signer::tests::generic_tests::test_sign_transaction;

    log::debug!("sign_transaction, seed = {seed:?}");

    let _join_guard = maybe_spawn_auto_confirmer();

    let mut rng = make_seedable_rng(seed);

    test_sign_transaction(&mut rng, trezor_signer);
}
