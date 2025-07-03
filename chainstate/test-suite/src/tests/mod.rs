// Copyright (c) 2022 RBB S.r.l
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
use std::sync::Mutex;

use chainstate::BlockSource;
use chainstate_test_framework::TestFramework;
use common::{
    chain::{signature::inputsig::InputWitness, Block, GenBlock, Genesis},
    primitives::{BlockHeight, Id},
};
use randomness::Rng;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

mod basic_tests;
mod block_invalidation;
mod block_status;
mod bootstrap;
mod chainstate_accounting_storage_tests;
mod chainstate_storage_tests;
mod data_deposit;
mod delegation_tests;
mod double_spend_tests;
mod events_tests;
mod framework_tests;
mod fungible_tokens;
mod fungible_tokens_v1;
mod get_stake_pool_balances_at_heights;
mod history_iteration;
mod homomorphism;
mod htlc;
mod initialization;
mod input_commitments;
mod mempool_output_timelock;
mod nft_burn;
mod nft_issuance;
mod nft_reorgs;
mod nft_transfer;
mod orders_tests;
mod output_timelock;
mod pos_accounting_reorg;
mod pos_maturity_settings;
mod pos_processing_tests;
mod pos_retargeting_tests;
mod processing_tests;
mod reorgs_tests;
mod signature_tests;
mod stake_pool_tests;
mod syncing_tests;
mod tx_fee;
mod tx_verification_simulation;
mod tx_verifier_among_threads;
mod tx_verifier_disconnect;

mod helpers;

type EventList = Arc<Mutex<Vec<(Id<Block>, BlockHeight)>>>;

#[ctor::ctor]
fn init() {
    logging::init_logging();
}
