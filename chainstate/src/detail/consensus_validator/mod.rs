// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use chainstate_types::block_index::BlockIndex;
use chainstate_types::preconnect_data::ConsensusExtraData;
use chainstate_types::stake_modifer::PoSStakeModifier;

use common::chain::block::BlockHeader;
use common::chain::block::ConsensusData;
use common::chain::config::ChainConfig;
use common::chain::{PoWStatus, RequiredConsensus};
use common::primitives::Idable;

use crate::detail::pow::work::check_pow_consensus;
use crate::BlockError;

pub use self::block_index_handle::BlockIndexHandle;
pub use self::transaction_index_handle::TransactionIndexHandle;

use super::pos::check_proof_of_stake;
use super::ConsensusVerificationError;

mod block_index_handle;
mod transaction_index_handle;

// TODO; using the transaction index itself is not good enough. We need an object that tracks the current state of the mainchain. This is a temporary solution
pub(crate) fn validate_consensus<H: BlockIndexHandle, T: TransactionIndexHandle>(
    chain_config: &ChainConfig,
    header: &BlockHeader,
    block_index_handle: &H,
    transaction_index_handle: &T,
) -> Result<(), ConsensusVerificationError> {
    let prev_block_id = *header.prev_block_id();

    let prev_block_height = block_index_handle
        .get_gen_block_index(&prev_block_id)
        .map_err(|err| {
            ConsensusVerificationError::PrevBlockLoadError(prev_block_id, header.get_id(), err)
        })?
        .ok_or_else(|| {
            ConsensusVerificationError::PrevBlockNotFound(prev_block_id, header.get_id())
        })?
        .block_height();

    let block_height = prev_block_height.next_height();
    let consensus_status = chain_config.net_upgrade().consensus_status(block_height);
    do_validate(
        chain_config,
        header,
        &consensus_status,
        block_index_handle,
        transaction_index_handle,
    )
}

pub fn compute_extra_consensus_data(
    prev_block_index: &BlockIndex,
    header: &BlockHeader,
) -> Result<ConsensusExtraData, BlockError> {
    match header.consensus_data() {
        ConsensusData::None => Ok(ConsensusExtraData::None),
        ConsensusData::PoW(_) => Ok(ConsensusExtraData::None),
        ConsensusData::PoS(pos_data) => {
            let kernel_output = pos_data
                .kernel_inputs()
                .get(0)
                .ok_or_else(|| BlockError::PoSKernelInputNotFound(header.get_id()))?;
            let prev_stake_modifier = prev_block_index.preconnect_data().stake_modifier();
            let stake_modifer =
                PoSStakeModifier::from_new_block(prev_stake_modifier, kernel_output.outpoint());
            let data = ConsensusExtraData::PoS(stake_modifer);
            Ok(data)
        }
    }
}

fn validate_pow_consensus<H: BlockIndexHandle>(
    chain_config: &ChainConfig,
    header: &BlockHeader,
    pow_status: &PoWStatus,
    block_index_handle: &H,
) -> Result<(), ConsensusVerificationError> {
    match header.consensus_data() {
        ConsensusData::None | ConsensusData::PoS(_) => {
            Err(ConsensusVerificationError::ConsensusTypeMismatch(
                "Chain configuration says we are PoW but block consensus data is not PoW.".into(),
            ))
        }
        ConsensusData::PoW(_) => {
            check_pow_consensus(chain_config, header, pow_status, block_index_handle)
                .map_err(Into::into)
        }
    }
}

fn validate_ignore_consensus(header: &BlockHeader) -> Result<(), ConsensusVerificationError> {
    match header.consensus_data() {
        ConsensusData::None => Ok(()),
        ConsensusData::PoW(_)|ConsensusData::PoS(_) => Err(ConsensusVerificationError::ConsensusTypeMismatch(
            "Chain configuration says consensus should be empty but block consensus data is not `None`.".into(),
        )),
    }
}

fn validate_pos_consensus<H: BlockIndexHandle, T: TransactionIndexHandle>(
    chain_config: &ChainConfig,
    block_index_handle: &H,
    transaction_index_handle: &T,
    header: &BlockHeader,
) -> Result<(), ConsensusVerificationError> {
    match header.consensus_data() {
        ConsensusData::None | ConsensusData::PoW(_)=>  Err(ConsensusVerificationError::ConsensusTypeMismatch(
            "Chain configuration says consensus should be empty but block consensus data is not `None`.".into(),
        )),
        ConsensusData::PoS(pos_data) => check_proof_of_stake(chain_config,  header, pos_data, block_index_handle, transaction_index_handle).map_err(Into::into),
    }
}

fn do_validate<H: BlockIndexHandle, T: TransactionIndexHandle>(
    chain_config: &ChainConfig,
    header: &BlockHeader,
    consensus_status: &RequiredConsensus,
    block_index_handle: &H,
    transaction_index_handle: &T,
) -> Result<(), ConsensusVerificationError> {
    match consensus_status {
        RequiredConsensus::PoW(pow_status) => {
            validate_pow_consensus(chain_config, header, pow_status, block_index_handle)
        }
        RequiredConsensus::IgnoreConsensus => validate_ignore_consensus(header),
        RequiredConsensus::PoS => validate_pos_consensus(
            chain_config,
            block_index_handle,
            transaction_index_handle,
            header,
        ),
        RequiredConsensus::DSA => Err(ConsensusVerificationError::UnsupportedConsensusType),
    }
}
