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

use crate::TestFramework;
use chainstate::BlockSource;
use common::{
    chain::{
        config::create_regtest, signature::inputsig::InputWitness, Block, GenBlock, Genesis,
        OutputPurpose,
    },
    primitives::{BlockHeight, Id},
    Uint256,
};
use crypto::random::Rng;
use rstest::rstest;
use serialization::Encode;
use test_utils::random::{make_seedable_rng, Seed};

mod double_spend_tests;
mod events_tests;
mod output_timelock;
mod processing_tests;
mod reorgs_tests;
mod signature_tests;
mod syncing_tests;

type EventList = Arc<Mutex<Vec<(Id<Block>, BlockHeight)>>>;

// Generate 5 regtest blocks and print their hex encoding, which is useful for functional tests.
// TODO: remove when block production is ready
#[ignore]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn generate_blocks_for_functional_tests(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut tf = TestFramework::builder().with_chain_config(create_regtest()).build();
    let difficulty =
        Uint256([0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF]);

    for _ in 1..6 {
        let mut mined_block = tf.make_block_builder().add_test_transaction(&mut rng).build();
        let bits = difficulty.into();
        assert!(consensus::pow::mine(&mut mined_block, u128::MAX, bits)
            .expect("Unexpected conversion error"));
        println!("{}", hex::encode(mined_block.encode()));
        tf.process_block(mined_block, BlockSource::Local).unwrap();
    }
}
