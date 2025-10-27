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

use std::sync::{Arc, Mutex};

use rstest::rstest;
use serial_test::serial;

use ::test_utils::random::{make_seedable_rng, Seed};
use common::chain::{ChainConfig, SighashInputCommitmentVersion};
use crypto::key::{hdkd::u31::U31, PredefinedSigAuxDataProvider};
use logging::log;

use crate::signer::{
    tests::{
        generic_fixed_signature_tests::{
            test_fixed_signatures_generic, test_fixed_signatures_generic2,
            test_fixed_signatures_generic_htlc_refunding,
        },
        generic_tests::{
            test_sign_message_generic, test_sign_transaction_generic,
            test_sign_transaction_intent_generic, MessageToSign,
        },
        make_deterministic_software_signer, no_another_signer,
    },
    trezor_signer::{test_utils::find_test_device_and_connect, TrezorSigner},
};

use super::test_utils::maybe_spawn_auto_confirmer;

pub fn make_trezor_signer(chain_config: Arc<ChainConfig>, _account_index: U31) -> TrezorSigner {
    let mut client = find_test_device_and_connect(false);
    let session_id = client.initialize(None).unwrap().ok().unwrap().session_id().to_vec();

    TrezorSigner::new(chain_config, Arc::new(Mutex::new(client)), session_id)
}

// Return a TrezorSigner that always produces Trezor-like signatures.
// (Note: the default TrezorSigner will still produce non-deterministic signatures when using
// standalone keys.)
pub fn make_deterministic_trezor_signer(
    chain_config: Arc<ChainConfig>,
    _account_index: U31,
) -> TrezorSigner {
    let mut client = find_test_device_and_connect(false);
    let session_id = client.initialize(None).unwrap().ok().unwrap().session_id().to_vec();

    TrezorSigner::new_with_sig_aux_data_provider(
        chain_config,
        Arc::new(Mutex::new(client)),
        session_id,
        Box::new(PredefinedSigAuxDataProvider),
    )
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
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sign_message(
    #[case] seed: Seed,
    #[values(
        MessageToSign::Random,
        // Special case: an "overlong" utf-8 string (basically, the letter 'K' encoded with 2 bytes
        // instead of 1). The firmware used to have troubles with this.
        MessageToSign::Predefined(vec![193, 139])
    )]
    message_to_sign: MessageToSign,
) {
    log::debug!("test_sign_message, seed = {seed:?}");

    let _join_guard = maybe_spawn_auto_confirmer();

    let mut rng = make_seedable_rng(seed);

    test_sign_message_generic(
        &mut rng,
        message_to_sign,
        make_trezor_signer,
        no_another_signer(),
    )
    .await;
}

#[rstest]
#[trace]
#[serial]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sign_transaction_intent(#[case] seed: Seed) {
    log::debug!("test_sign_transaction_intent, seed = {seed:?}");

    let _join_guard = maybe_spawn_auto_confirmer();

    let mut rng = make_seedable_rng(seed);

    test_sign_transaction_intent_generic(&mut rng, make_trezor_signer, no_another_signer()).await;
}

#[rstest]
#[trace]
#[serial]
#[case(Seed::from_entropy(), SighashInputCommitmentVersion::V0)]
#[trace]
#[serial]
#[case(Seed::from_entropy(), SighashInputCommitmentVersion::V1)]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sign_transaction(
    #[case] seed: Seed,
    #[case] input_commitments_version: SighashInputCommitmentVersion,
) {
    log::debug!("test_sign_transaction, seed = {seed:?}, input_commitments_version = {input_commitments_version:?}");

    let _join_guard = maybe_spawn_auto_confirmer();

    let mut rng = make_seedable_rng(seed);

    test_sign_transaction_generic(
        &mut rng,
        input_commitments_version,
        make_trezor_signer,
        no_another_signer(),
    )
    .await;
}

#[rstest]
#[trace]
#[serial]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_fixed_signatures(#[case] seed: Seed) {
    log::debug!("test_fixed_signatures, seed = {seed:?}");

    let _join_guard = maybe_spawn_auto_confirmer();

    let mut rng = make_seedable_rng(seed);

    test_fixed_signatures_generic(&mut rng, make_deterministic_trezor_signer).await;
}

#[rstest]
#[trace]
#[serial]
#[case(Seed::from_entropy(), SighashInputCommitmentVersion::V0)]
#[trace]
#[serial]
#[case(Seed::from_entropy(), SighashInputCommitmentVersion::V1)]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_fixed_signatures2(
    #[case] seed: Seed,
    #[case] input_commitments_version: SighashInputCommitmentVersion,
) {
    log::debug!("test_fixed_signatures2, seed = {seed:?}, input_commitments_version = {input_commitments_version:?}");

    let _join_guard = maybe_spawn_auto_confirmer();

    let mut rng = make_seedable_rng(seed);

    test_fixed_signatures_generic2(
        &mut rng,
        input_commitments_version,
        make_deterministic_trezor_signer,
    )
    .await;
}

#[rstest]
#[trace]
#[serial]
#[case(Seed::from_entropy(), SighashInputCommitmentVersion::V0)]
#[trace]
#[serial]
#[case(Seed::from_entropy(), SighashInputCommitmentVersion::V1)]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_fixed_signatures_htlc_refunding(
    #[case] seed: Seed,
    #[case] input_commitments_version: SighashInputCommitmentVersion,
) {
    log::debug!("test_fixed_signatures_htlc_refunding, seed = {seed:?}, input_commitments_version = {input_commitments_version:?}");

    let _join_guard = maybe_spawn_auto_confirmer();

    let mut rng = make_seedable_rng(seed);

    test_fixed_signatures_generic_htlc_refunding(
        &mut rng,
        input_commitments_version,
        make_deterministic_trezor_signer,
    )
    .await;
}

#[rstest]
#[trace]
#[serial]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sign_message_sig_consistency(#[case] seed: Seed) {
    log::debug!("test_sign_message_sig_consistency, seed = {seed:?}");

    let _join_guard = maybe_spawn_auto_confirmer();

    let mut rng = make_seedable_rng(seed);

    test_sign_message_generic(
        &mut rng,
        MessageToSign::Random,
        make_deterministic_trezor_signer,
        Some(make_deterministic_software_signer),
    )
    .await;
}

#[rstest]
#[trace]
#[serial]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sign_transaction_intent_sig_consistency(#[case] seed: Seed) {
    log::debug!("test_sign_transaction_intent_sig_consistency, seed = {seed:?}");

    let _join_guard = maybe_spawn_auto_confirmer();

    let mut rng = make_seedable_rng(seed);

    test_sign_transaction_intent_generic(
        &mut rng,
        make_deterministic_trezor_signer,
        Some(make_deterministic_software_signer),
    )
    .await;
}

#[rstest]
#[trace]
#[serial]
#[case(Seed::from_entropy(), SighashInputCommitmentVersion::V0)]
#[trace]
#[serial]
#[case(Seed::from_entropy(), SighashInputCommitmentVersion::V1)]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sign_transaction_sig_consistency(
    #[case] seed: Seed,
    #[case] input_commitments_version: SighashInputCommitmentVersion,
) {
    log::debug!("test_sign_transaction_sig_consistency, seed = {seed:?}, input_commitments_version = {input_commitments_version:?}");

    let _join_guard = maybe_spawn_auto_confirmer();

    let mut rng = make_seedable_rng(seed);

    test_sign_transaction_generic(
        &mut rng,
        input_commitments_version,
        make_deterministic_trezor_signer,
        Some(make_deterministic_software_signer),
    )
    .await;
}
