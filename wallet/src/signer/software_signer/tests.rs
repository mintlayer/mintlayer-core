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

use common::chain::SighashInputCommitmentVersion;
use test_utils::random::{make_seedable_rng, Seed};

use crate::signer::tests::{
    generic_fixed_signature_tests::{
        test_fixed_signatures_generic, test_fixed_signatures_generic2,
        test_fixed_signatures_generic_htlc_refunding,
    },
    generic_tests::{
        test_sign_message_generic, test_sign_transaction_generic,
        test_sign_transaction_intent_generic, MessageToSign,
    },
    make_deterministic_software_signer, make_software_signer, no_another_signer,
};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_sign_message(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    test_sign_message_generic(
        &mut rng,
        MessageToSign::Random,
        make_software_signer,
        no_another_signer(),
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_sign_transaction_intent(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    test_sign_transaction_intent_generic(&mut rng, make_software_signer, no_another_signer());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), SighashInputCommitmentVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), SighashInputCommitmentVersion::V1)]
fn test_sign_transaction(
    #[case] seed: Seed,
    #[case] input_commitments_version: SighashInputCommitmentVersion,
) {
    let mut rng = make_seedable_rng(seed);

    test_sign_transaction_generic(
        &mut rng,
        input_commitments_version,
        make_software_signer,
        no_another_signer(),
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_fixed_signatures(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    test_fixed_signatures_generic(&mut rng, make_deterministic_software_signer);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), SighashInputCommitmentVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), SighashInputCommitmentVersion::V1)]
fn test_fixed_signatures2(
    #[case] seed: Seed,
    #[case] input_commitments_version: SighashInputCommitmentVersion,
) {
    let mut rng = make_seedable_rng(seed);

    test_fixed_signatures_generic2(
        &mut rng,
        input_commitments_version,
        make_deterministic_software_signer,
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), SighashInputCommitmentVersion::V0)]
#[trace]
#[case(Seed::from_entropy(), SighashInputCommitmentVersion::V1)]
fn test_fixed_signatures_htlc_refunding(
    #[case] seed: Seed,
    #[case] input_commitments_version: SighashInputCommitmentVersion,
) {
    let mut rng = make_seedable_rng(seed);

    test_fixed_signatures_generic_htlc_refunding(
        &mut rng,
        input_commitments_version,
        make_deterministic_software_signer,
    );
}
