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

use super::*;
use chainstate_test_framework::TxVerificationStrategy;

#[rstest]
#[trace]
#[case(Seed::from_entropy(), 20, 50)]
fn simulation(#[case] seed: Seed, #[case] max_blocks: usize, #[case] max_tx_per_block: usize) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder()
            .with_tx_verification_strategy(TxVerificationStrategy::Randomized(seed))
            .build();

        for _ in 0..rng.gen_range(10..max_blocks) {
            println!("***************************************** Building a block");
            let mut block_builder = tf.make_block_builder();

            for _ in 0..rng.gen_range(10..max_tx_per_block) {
                block_builder = block_builder.add_test_transaction(&mut rng);
            }
            block_builder.build_and_process().unwrap().unwrap();
        }
    });
}
