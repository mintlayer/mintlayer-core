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
#[case(Seed::from_entropy(), 20, 50, false)]
#[case(Seed::from_entropy(), 20, 50, true)]
fn simulation(
    #[case] seed: Seed,
    #[case] max_blocks: usize,
    #[case] max_tx_per_block: usize,
    #[case] tx_index_enabled: bool,
) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_chainstate_config(chainstate::ChainstateConfig {
                tx_index_enabled: tx_index_enabled.into(),
                max_db_commit_attempts: Default::default(),
                max_orphan_blocks: Default::default(),
                min_max_bootstrap_import_buffer_sizes: Default::default(),
                max_tip_age: Default::default(),
            })
            .with_tx_verification_strategy(TxVerificationStrategy::Randomized(seed))
            .build();

        for _ in 0..rng.gen_range(10..max_blocks) {
            let mut block_builder = tf.make_block_builder();

            for _ in 0..rng.gen_range(10..max_tx_per_block) {
                block_builder = block_builder.add_test_transaction(&mut rng);
            }
            block_builder.build_and_process().unwrap().unwrap();
        }
    });
}
