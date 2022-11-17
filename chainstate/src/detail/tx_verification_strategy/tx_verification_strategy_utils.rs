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

use std::collections::VecDeque;

use common::{
    chain::{calculate_tx_offsets_in_block, Block, TxMainChainIndex, TxMainChainIndexError},
    primitives::Idable,
};
use tx_verifier::transaction_verifier::{error::TxIndexError, TransactionVerifierConfig};

pub fn take_tx_index(
    tx_indices: &mut Option<VecDeque<TxMainChainIndex>>,
) -> Option<TxMainChainIndex> {
    match tx_indices {
        Some(v) => v.pop_front(),
        None => None,
    }
}

fn assert_tx_indices_sanity(
    verifier_config: &TransactionVerifierConfig,
    tx_indices: &Option<VecDeque<TxMainChainIndex>>,
    block: &Block,
) {
    // Either tx_index is disabled, or enabled and tx count is equal to tx count in block
    assert!(
        !verifier_config.tx_index_enabled
            || tx_indices.as_ref().expect("Guaranteed by verifier config").len()
                == block.transactions().len()
    );
}

pub fn construct_tx_indices(
    verifier_config: &TransactionVerifierConfig,
    block: &Block,
) -> Result<Option<VecDeque<TxMainChainIndex>>, TxIndexError> {
    let tx_indices = verifier_config
        .if_tx_index_enabled(|| calculate_tx_offsets_in_block(block).map_err(TxIndexError::from));
    let tx_indices = tx_indices?;

    assert_tx_indices_sanity(verifier_config, &tx_indices, block);

    Ok(tx_indices)
}

pub fn construct_reward_tx_indices(
    verifier_config: &TransactionVerifierConfig,
    block: &Block,
) -> Result<Option<TxMainChainIndex>, TxIndexError> {
    let result = verifier_config.if_tx_index_enabled(|| {
        TxMainChainIndex::new(
            block.get_id().into(),
            block
                .block_reward()
                .outputs()
                .len()
                .try_into()
                .map_err(|_| TxMainChainIndexError::InvalidOutputCount)?,
        )
    })?;

    Ok(result)
}
