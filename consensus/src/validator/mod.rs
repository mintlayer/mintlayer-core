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

pub use self::{error::ExtraConsensusDataError, transaction_index_handle::TransactionIndexHandle};

mod transaction_index_handle;

use chainstate_types::{
    pos_randomness::PoSRandomness, preconnect_data::ConsensusExtraData, BlockIndex,
    BlockIndexHandle,
};
use common::{
    chain::{
        block::{consensus_data::PoSData, BlockHeader, ConsensusData},
        config::ChainConfig,
        PoWStatus, RequiredConsensus,
    },
    primitives::Idable,
};

pub mod error;

use crate::{
    error::ConsensusVerificationError,
    pos::{check_proof_of_stake, kernel::get_kernel_output},
    pow::check_pow_consensus,
};

/// Checks if the given block identified by the header contains the correct consensus data.  
pub fn validate_consensus<H: BlockIndexHandle, T: TransactionIndexHandle>(
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

fn compute_current_randomness<H: BlockIndexHandle, T: TransactionIndexHandle>(
    chain_config: &ChainConfig,
    pos_data: &PoSData,
    prev_block_index: &BlockIndex,
    header: &BlockHeader,
    block_index_handle: &H,
    tx_index_retriever: &T,
) -> Result<PoSRandomness, ExtraConsensusDataError> {
    let prev_randomness = prev_block_index.preconnect_data().pos_randomness();
    let kernel_output = get_kernel_output(pos_data, block_index_handle, tx_index_retriever)
        .map_err(|_| ExtraConsensusDataError::PoSKernelOutputRetrievalFailed(header.get_id()))?;
    let current_randomness = PoSRandomness::from_new_block(
        chain_config,
        prev_randomness,
        prev_block_index,
        header,
        &kernel_output,
        pos_data,
    )?;
    Ok(current_randomness)
}

pub fn compute_extra_consensus_data<H: BlockIndexHandle, T: TransactionIndexHandle>(
    chain_config: &ChainConfig,
    prev_block_index: &BlockIndex,
    header: &BlockHeader,
    block_index_handle: &H,
    tx_index_retriever: &T,
) -> Result<ConsensusExtraData, ExtraConsensusDataError> {
    match header.consensus_data() {
        ConsensusData::None => Ok(ConsensusExtraData::None),
        ConsensusData::PoW(_) => Ok(ConsensusExtraData::None),
        ConsensusData::PoS(pos_data) => {
            let current_randomness = compute_current_randomness(
                chain_config,
                pos_data,
                prev_block_index,
                header,
                block_index_handle,
                tx_index_retriever,
            )?;
            let data = ConsensusExtraData::PoS(current_randomness);
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
