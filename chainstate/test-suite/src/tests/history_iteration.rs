// Copyright (c) 2021-2022 RBB S.r.l
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

use chainstate::BlockSource;
use chainstate_storage::Transactional;
use chainstate_test_framework::{TestBlockIndexHandle, TestFramework};
use chainstate_types::BlockIndexHistoryIterator;
use common::primitives::{Id, Idable, H256};
use test_utils::random::{make_seedable_rng, Seed};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn history_iteration(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        // put three blocks in a chain after genesis
        let block1 = tf.make_block_builder().build(&mut rng);
        tf.process_block(block1.clone(), BlockSource::Local).unwrap();

        let block2 = tf.make_block_builder().build(&mut rng);
        tf.process_block(block2.clone(), BlockSource::Local).unwrap();

        let block3 = tf.make_block_builder().build(&mut rng);
        tf.process_block(block3.clone(), BlockSource::Local).unwrap();

        ///// test history iterator - start from tip
        {
            let db_tx = tf.storage.transaction_ro().unwrap();
            let block_index_handle =
                TestBlockIndexHandle::new(db_tx, tf.chainstate.get_chain_config().as_ref());
            let mut iter =
                BlockIndexHistoryIterator::new(block3.get_id().into(), &block_index_handle);
            assert_eq!(iter.next().unwrap().block_id(), block3.get_id());
            assert_eq!(iter.next().unwrap().block_id(), block2.get_id());
            assert_eq!(iter.next().unwrap().block_id(), block1.get_id());
            assert_eq!(iter.next().unwrap().block_id(), tf.genesis().get_id());
            assert!(iter.next().is_none());
        }

        ///// test history iterator - start from genesis
        {
            //let chainstate_ref = tf.chainstate.();
            let db_tx = tf.storage.transaction_ro().unwrap();
            let block_index_handle =
                TestBlockIndexHandle::new(db_tx, tf.chainstate.get_chain_config().as_ref());
            let mut iter =
                BlockIndexHistoryIterator::new(tf.genesis().get_id().into(), &block_index_handle);
            assert_eq!(iter.next().unwrap().block_id(), tf.genesis().get_id(),);
            assert!(iter.next().is_none());
        }

        ///// test history iterator - start from an invalid non-existing block id
        {
            let db_tx = tf.storage.transaction_ro().unwrap();
            let block_index_handle =
                TestBlockIndexHandle::new(db_tx, tf.chainstate.get_chain_config().as_ref());
            let iter = BlockIndexHistoryIterator::new(Id::new(H256::zero()), &block_index_handle);

            assert!(iter.fuse().next().is_none());
        }
    });
}
