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
use common::chain::tokens::TokenCreator;
use common::{
    chain::{
        config::create_regtest, signature::inputsig::InputWitness, Block, GenBlock, Genesis,
        OutputPurpose,
    },
    primitives::{BlockHeight, Id},
    Uint256,
};
use crypto::key::{KeyKind, PrivateKey};
use crypto::random::distributions::uniform::SampleRange;
use crypto::random::Rng;
use rstest::rstest;
use serialization::Encode;
use test_utils::random::{make_seedable_rng, Seed};

mod bootstrap;
mod chainstate_storage_tests;
mod double_spend_tests;
mod events_tests;
mod fungible_tokens;

mod nft_burn;
mod nft_issuance;
mod nft_reorgs;
mod nft_transfer;
mod output_timelock;
mod processing_tests;
mod reorgs_tests;
mod signature_tests;
mod syncing_tests;

type EventList = Arc<Mutex<Vec<(Id<Block>, BlockHeight)>>>;

// FIXME(nft_issuance): This is the copy of function from check block. Remove copy and use this func from more appropriate place.
pub fn random_creator() -> Option<TokenCreator> {
    let (_, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    Some(TokenCreator::from(public_key))
}

//FIXME(nft_issuance): Move it in super mod and use for all tokens tests
pub fn random_string<R: SampleRange<usize>>(rng: &mut impl Rng, range_len: R) -> String {
    use crypto::random::distributions::{Alphanumeric, DistString};
    if range_len.is_empty() {
        return String::new();
    }
    let len = rng.gen_range(range_len);
    Alphanumeric.sample_string(rng, len)
}

//FIXME(nft_issuance): Move it in super mod and use for all tokens tests
fn gen_text_with_non_ascii(c: u8, rng: &mut impl Rng, max_len: usize) -> Vec<u8> {
    assert!(!c.is_ascii_alphanumeric());
    let text_len = 1 + rng.gen::<usize>() % max_len;
    let random_index_to_replace = rng.gen::<usize>() % text_len;
    let token_ticker: Vec<u8> = (0..text_len)
        .into_iter()
        .map(|idx| {
            if idx != random_index_to_replace {
                rng.sample(&crypto::random::distributions::Alphanumeric)
            } else {
                c
            }
        })
        .take(text_len)
        .collect();
    token_ticker
}

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
