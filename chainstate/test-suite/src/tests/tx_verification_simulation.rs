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
use chainstate_test_framework::{BlockBuilder, TestFramework, TxVerificationStrategy};

//enum Operation {
//    SpendCoin,
//    IssueToken,
//    TransferToken,
//    BurnToken,
//}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), 1000)]
fn coins_homomorphism(#[case] seed: Seed, #[case] total_iterations: usize) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::builder()
            .with_tx_verification_strategy(TxVerificationStrategy::Randomized(seed))
            .build();

        let mut rng = make_seedable_rng(seed);
        let mut block_builder: Option<BlockBuilder> = None;
        for _ in 0..rng.gen_range(0..total_iterations) {
            if block_builder.is_some() {
                if rng.gen::<bool>() {
                    block_builder.take().unwrap().build_and_process().unwrap().unwrap();
                } else {
                    block_builder = Some(block_builder.unwrap().add_test_transaction(&mut rng));
                }
            } else {
                block_builder = Some(tf.make_block_builder().add_test_transaction(&mut rng));
            }
        }
    });
}
