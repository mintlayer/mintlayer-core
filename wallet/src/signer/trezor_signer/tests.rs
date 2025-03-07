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

use super::*;
use rstest::rstest;
use serial_test::serial;
use test_utils::random::{make_seedable_rng, Seed};
use trezor_client::find_devices;

fn trezor_signer(chain_config: Arc<ChainConfig>, _account_index: U31) -> TrezorSigner {
    let mut client = find_test_device();
    let session_id = client.initialize(None).unwrap().ok().unwrap().session_id().to_vec();

    TrezorSigner::new(chain_config, Arc::new(Mutex::new(client)), session_id)
}

#[rstest]
#[trace]
#[serial]
#[case(Seed::from_entropy())]
fn sign_message(#[case] seed: Seed) {
    use crate::signer::signer_test_helpers::test_sign_message;

    let mut rng = make_seedable_rng(seed);

    test_sign_message(&mut rng, trezor_signer);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[serial]
fn sign_transaction_intent(#[case] seed: Seed) {
    use crate::signer::signer_test_helpers::test_sign_transaction_intent;

    let mut rng = make_seedable_rng(seed);

    test_sign_transaction_intent(&mut rng, trezor_signer);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[serial]
fn sign_transaction(#[case] seed: Seed) {
    use crate::signer::signer_test_helpers::test_sign_transaction;

    let mut rng = make_seedable_rng(seed);

    test_sign_transaction(&mut rng, trezor_signer);
}

fn find_test_device() -> Trezor {
    let use_real_device = std::env::var_os("TEST_REAL_DEVICE").is_some();

    let mut devices = find_devices(false)
        .into_iter()
        .filter(|device| device.model == Model::Trezor || device.model == Model::TrezorEmulator)
        .collect_vec();

    if use_real_device {
        // Try to find the first real device
        if let Some(idx) = devices.iter().position(|d| d.model == Model::Trezor) {
            return devices.swap_remove(idx).connect().unwrap();
        }
    }

    devices
        .into_iter()
        .find(|d| d.model == Model::TrezorEmulator)
        .unwrap()
        .connect()
        .unwrap()
}
