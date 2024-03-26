// Copyright (c) 2023 RBB S.r.l
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

use chainstate_test_framework::TestFramework;
use chainstate_types::{BlockStatus, BlockValidationStage};
use common::{chain::Block, primitives::Id};

pub fn get_block_status(tf: &TestFramework, block_id: &Id<Block>) -> BlockStatus {
    tf.block_index(block_id.into()).status()
}

pub fn assert_fully_valid_block(block_status: BlockStatus) {
    assert!(block_status.is_ok());
    assert!(block_status.is_fully_valid());
}

pub fn assert_bad_block_at_stage(
    block_status: BlockStatus,
    expected_last_valid_stage: BlockValidationStage,
) {
    assert_eq!(block_status.last_valid_stage(), expected_last_valid_stage);
    assert!(block_status.validation_failed());
    assert!(!block_status.has_invalid_parent());
    assert!(!block_status.is_explicitly_invalidated());
}

pub fn assert_block_with_bad_parent_at_stage(
    block_status: BlockStatus,
    expected_last_valid_stage: BlockValidationStage,
) {
    assert_eq!(block_status.last_valid_stage(), expected_last_valid_stage);
    assert!(!block_status.validation_failed());
    assert!(block_status.has_invalid_parent());
    assert!(!block_status.is_explicitly_invalidated());
}

pub fn assert_invalidated_block_at_stage(
    block_status: BlockStatus,
    expected_last_valid_stage: BlockValidationStage,
) {
    assert_eq!(block_status.last_valid_stage(), expected_last_valid_stage);
    assert!(!block_status.validation_failed());
    assert!(!block_status.has_invalid_parent());
    assert!(block_status.is_explicitly_invalidated());
}

pub fn assert_bad_block_with_bad_parent_at_stage(
    block_status: BlockStatus,
    expected_last_valid_stage: BlockValidationStage,
) {
    assert_eq!(block_status.last_valid_stage(), expected_last_valid_stage);
    assert!(block_status.validation_failed());
    assert!(block_status.has_invalid_parent());
    assert!(!block_status.is_explicitly_invalidated());
}

pub fn assert_invalidated_block_with_bad_parent_at_stage(
    block_status: BlockStatus,
    expected_last_valid_stage: BlockValidationStage,
) {
    assert_eq!(block_status.last_valid_stage(), expected_last_valid_stage);
    assert!(!block_status.validation_failed());
    assert!(block_status.has_invalid_parent());
    assert!(block_status.is_explicitly_invalidated());
}

pub fn assert_ok_block_at_stage(
    block_status: BlockStatus,
    expected_last_valid_stage: BlockValidationStage,
) {
    assert!(block_status.is_ok());
    assert_eq!(block_status.last_valid_stage(), expected_last_valid_stage);
}

pub fn assert_in_main_chain(tf: &TestFramework, block_ids: &[Id<Block>]) {
    for block_id in block_ids {
        assert!(tf.is_block_in_main_chain(block_id));
    }
}

pub fn assert_in_stale_chain(tf: &TestFramework, block_ids: &[Id<Block>]) {
    for block_id in block_ids {
        assert!(!tf.is_block_in_main_chain(block_id));
    }
}

pub fn assert_fully_valid_blocks(tf: &TestFramework, block_ids: &[Id<Block>]) {
    for block_id in block_ids {
        let block_status = get_block_status(tf, block_id);
        assert_fully_valid_block(block_status);
    }
}

pub fn assert_no_block_indices(tf: &TestFramework, block_ids: &[Id<Block>]) {
    for block_id in block_ids {
        assert!(
            !tf.block_index_exists(block_id.into()),
            "Block {block_id} index must not exist"
        );
    }
}

pub fn assert_ok_blocks_at_stage(
    tf: &TestFramework,
    block_ids: &[Id<Block>],
    expected_last_valid_stage: BlockValidationStage,
) {
    for block_id in block_ids {
        let block_status = get_block_status(tf, block_id);
        assert_ok_block_at_stage(block_status, expected_last_valid_stage);
    }
}

pub fn assert_bad_blocks_at_stage(
    tf: &TestFramework,
    block_ids: &[Id<Block>],
    expected_last_valid_stage: BlockValidationStage,
) {
    for block_id in block_ids {
        let block_status = get_block_status(tf, block_id);
        assert_bad_block_at_stage(block_status, expected_last_valid_stage);
    }
}

pub fn assert_blocks_with_bad_parent_at_stage(
    tf: &TestFramework,
    block_ids: &[Id<Block>],
    expected_last_valid_stage: BlockValidationStage,
) {
    for block_id in block_ids {
        let block_status = get_block_status(tf, block_id);
        assert_block_with_bad_parent_at_stage(block_status, expected_last_valid_stage);
    }
}

pub fn assert_invalidated_blocks_at_stage(
    tf: &TestFramework,
    block_ids: &[Id<Block>],
    expected_last_valid_stage: BlockValidationStage,
) {
    for block_id in block_ids {
        let block_status = get_block_status(tf, block_id);
        assert_invalidated_block_at_stage(block_status, expected_last_valid_stage);
    }
}

pub fn assert_bad_blocks_with_bad_parent_at_stage(
    tf: &TestFramework,
    block_ids: &[Id<Block>],
    expected_last_valid_stage: BlockValidationStage,
) {
    for block_id in block_ids {
        let block_status = get_block_status(tf, block_id);
        assert_bad_block_with_bad_parent_at_stage(block_status, expected_last_valid_stage);
    }
}

pub fn assert_invalidated_blocks_with_bad_parent_at_stage(
    tf: &TestFramework,
    block_ids: &[Id<Block>],
    expected_last_valid_stage: BlockValidationStage,
) {
    for block_id in block_ids {
        let block_status = get_block_status(tf, block_id);
        assert_invalidated_block_with_bad_parent_at_stage(block_status, expected_last_valid_stage);
    }
}
