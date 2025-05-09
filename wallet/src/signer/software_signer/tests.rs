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

use std::sync::Arc;

use rstest::rstest;

use common::chain::ChainConfig;
use crypto::key::hdkd::u31::U31;
use test_utils::random::{make_seedable_rng, Seed};

use super::*;

fn software_signer(chain_config: Arc<ChainConfig>, account_index: U31) -> SoftwareSigner {
    SoftwareSigner::new(chain_config, account_index)
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn sign_message(#[case] seed: Seed) {
    use crate::signer::tests::generic_tests::test_sign_message;

    let mut rng = make_seedable_rng(seed);

    test_sign_message(&mut rng, software_signer);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn sign_transaction_intent(#[case] seed: Seed) {
    use crate::signer::tests::generic_tests::test_sign_transaction_intent;

    let mut rng = make_seedable_rng(seed);

    test_sign_transaction_intent(&mut rng, software_signer);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn sign_transaction(#[case] seed: Seed) {
    use crate::signer::tests::generic_tests::test_sign_transaction;

    let mut rng = make_seedable_rng(seed);

    test_sign_transaction(&mut rng, software_signer);
}
