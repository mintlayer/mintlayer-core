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

use chainstate_types::BlockIndexHandle;
use common::{
    chain::{
        block::{BlockHeader, ConsensusData},
        config::ChainConfig,
        PoWStatus, RequiredConsensus,
    },
    primitives::Idable,
};
use pos_accounting::PoSAccountingView;
use utxo::UtxosView;

use crate::{
    error::ConsensusVerificationError, pos::check_proof_of_stake, pow::check_pow_consensus,
};

/// Checks if the given block identified by the header contains the correct consensus data.
pub fn validate_consensus<H, U, P>(
    chain_config: &ChainConfig,
    header: &BlockHeader,
    block_index_handle: &H,
    utxos_view: &U,
    pos_accounting_view: &P,
) -> Result<(), ConsensusVerificationError>
where
    H: BlockIndexHandle,
    U: UtxosView,
    P: PoSAccountingView,
{
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
    match consensus_status {
        RequiredConsensus::PoW(pow_status) => {
            validate_pow_consensus(chain_config, header, &pow_status, block_index_handle)
        }
        RequiredConsensus::IgnoreConsensus => validate_ignore_consensus(header),
        RequiredConsensus::PoS => validate_pos_consensus(
            chain_config,
            block_index_handle,
            utxos_view,
            pos_accounting_view,
            header,
        ),
        RequiredConsensus::DSA => Err(ConsensusVerificationError::UnsupportedConsensusType),
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
        ConsensusData::PoW(pow_data) => check_pow_consensus(
            chain_config,
            header,
            pow_data,
            pow_status,
            block_index_handle,
        )
        .map_err(Into::into),
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

fn validate_pos_consensus<H, U, P>(
    chain_config: &ChainConfig,
    block_index_handle: &H,
    utxos_view: &U,
    pos_accounting_view: &P,
    header: &BlockHeader,
) -> Result<(), ConsensusVerificationError>
where
    H: BlockIndexHandle,
    U: UtxosView,
    P: PoSAccountingView,
{
    match header.consensus_data() {
        ConsensusData::None | ConsensusData::PoW(_) => {
            Err(ConsensusVerificationError::ConsensusTypeMismatch(
                "Chain configuration says we are PoS but block consensus data is not PoS.".into(),
            ))
        }
        ConsensusData::PoS(pos_data) => check_proof_of_stake(
            chain_config,
            header,
            pos_data,
            block_index_handle,
            utxos_view,
            pos_accounting_view,
        )
        .map_err(Into::into),
    }
}
