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

use crate::{
    pos::{error::ConsensusPoSError, target::calculate_target_required_from_block_index},
    ConsensusCreationError,
};
use chainstate_types::{
    pos_randomness::PoSRandomness, vrf_tools::construct_transcript, BlockIndex, GenBlockIndex,
};
use common::{
    chain::{
        block::{
            consensus_data::PoSData, timestamp::BlockTimestamp, BlockReward,
            BlockRewardTransactable,
        },
        config::EpochIndex,
        signature::{
            inputsig::{
                authorize_pubkey_spend::sign_public_key_spending,
                standard_signature::StandardInputSignature, InputWitness,
            },
            sighash::{sighashtype::SigHashType, signature_hash},
        },
        ChainConfig, Destination, PoSStatus, PoolId, TxInput, TxOutput,
    },
    primitives::{Amount, BlockHeight},
};
use crypto::{
    key::{PrivateKey, PublicKey, SigAuxDataProvider},
    vrf::{VRFPrivateKey, VRFPublicKey},
};
use serialization::{Decode, Encode};

/// Input needed to generate PoS consensus data
///
/// This struct will be provided by a wallet via `blockprod` RPC calls
/// in order to generate Proof-of-Stake consensus data (see
/// ConsensusData::PoS for more info) when creating PoS blocks.
///
/// The `stake_private_key` is used to know who will receive the block
/// reward and to sign block headers.
///
/// The `vrf_private_key` and `pool_id` will be used to calculate the
/// target threshold for staking (i.e the stake pool's balance will be
/// used as an input into the calculations).
///
/// And the `kernel_inputs` are the wallet-provided `TxInput(s)` that
/// the staker will spend in order to stake a new block, whilst
/// `kernel_input_utxos` are the UTXOs that the `kernel_inputs` point
/// to, which will be used to sign the PoS consensus data
/// `kernel_witness`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct PoSGenerateBlockInputData {
    /// The private key of the staker
    stake_private_key: PrivateKey,
    /// The VRF private key (i.e used for sealed epoch data)
    vrf_private_key: VRFPrivateKey,
    /// The pool Id of stake pool
    pool_id: PoolId,
    /// The transaction input for the block reward
    kernel_inputs: Vec<TxInput>,
    /// The transaction input UTXOs
    kernel_input_utxos: Vec<TxOutput>,
}

impl PoSGenerateBlockInputData {
    pub fn new(
        stake_private_key: PrivateKey,
        vrf_private_key: VRFPrivateKey,
        pool_id: PoolId,
        kernel_inputs: Vec<TxInput>,
        kernel_input_utxos: Vec<TxOutput>,
    ) -> Self {
        Self {
            stake_private_key,
            vrf_private_key,
            pool_id,
            kernel_inputs,
            kernel_input_utxos,
        }
    }

    pub fn kernel_inputs(&self) -> &Vec<TxInput> {
        &self.kernel_inputs
    }

    pub fn kernel_input_utxos(&self) -> &Vec<TxOutput> {
        &self.kernel_input_utxos
    }

    pub fn pool_id(&self) -> PoolId {
        self.pool_id
    }

    pub fn stake_private_key(&self) -> &PrivateKey {
        &self.stake_private_key
    }

    pub fn stake_public_key(&self) -> PublicKey {
        PublicKey::from_private_key(&self.stake_private_key)
    }

    pub fn vrf_private_key(&self) -> &VRFPrivateKey {
        &self.vrf_private_key
    }
}

/// Input data for the timestamp searching
///
/// Note: since the struct contains the vrf private key, it must be
/// encrypted when transmitting it over rpc.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct PoSTimestampSearchInputData {
    pool_id: PoolId,
    vrf_private_key: VRFPrivateKey,
}

impl PoSTimestampSearchInputData {
    pub fn new(pool_id: PoolId, vrf_private_key: VRFPrivateKey) -> Self {
        Self {
            pool_id,
            vrf_private_key,
        }
    }

    pub fn pool_id(&self) -> &PoolId {
        &self.pool_id
    }

    pub fn vrf_private_key(&self) -> &VRFPrivateKey {
        &self.vrf_private_key
    }
}

/// Input needed to finalize PoS consensus data
///
/// This struct is an internal data structure that will be created by
/// `blockprod`, and will be used when finalizing Proof-of-Stake consensus
/// data (see ConsensusData::PoS for more info) during PoS block creation.
#[derive(Debug, Clone)]
pub struct PoSFinalizeBlockInputData {
    /// The private key of the staker
    stake_private_key: PrivateKey,
    /// The VRF private key (i.e used for sealed epoch data)
    vrf_private_key: VRFPrivateKey,
    /// The epoch index of the height of the new block
    epoch_index: EpochIndex,
    /// The sealed epoch randomness (i.e used in producing VRF data)
    sealed_epoch_randomness: PoSRandomness,
    /// The amount pledged to the pool
    pledge_amount: Amount,
    /// The current pool balance of the stake pool
    pool_balance: Amount,
}

impl PoSFinalizeBlockInputData {
    pub fn new(
        stake_private_key: PrivateKey,
        vrf_private_key: VRFPrivateKey,
        epoch_index: EpochIndex,
        sealed_epoch_randomness: PoSRandomness,
        pledge_amount: Amount,
        pool_balance: Amount,
    ) -> Self {
        Self {
            stake_private_key,
            vrf_private_key,
            epoch_index,
            sealed_epoch_randomness,
            pledge_amount,
            pool_balance,
        }
    }

    pub fn epoch_index(&self) -> EpochIndex {
        self.epoch_index
    }

    pub fn pool_balance(&self) -> Amount {
        self.pool_balance
    }

    pub fn sealed_epoch_randomness(&self) -> &PoSRandomness {
        &self.sealed_epoch_randomness
    }

    pub fn stake_private_key(&self) -> &PrivateKey {
        &self.stake_private_key
    }

    pub fn vrf_private_key(&self) -> &VRFPrivateKey {
        &self.vrf_private_key
    }

    pub fn vrf_public_key(&self) -> VRFPublicKey {
        VRFPublicKey::from_private_key(&self.vrf_private_key)
    }

    pub fn pledge_amount(&self) -> Amount {
        self.pledge_amount
    }
}

#[allow(clippy::too_many_arguments)]
pub fn generate_pos_consensus_data_and_reward<G, AuxP: SigAuxDataProvider + ?Sized>(
    chain_config: &ChainConfig,
    prev_block_index: &GenBlockIndex,
    pos_input_data: &PoSGenerateBlockInputData,
    pos_status: &PoSStatus,
    sealed_epoch_randomness: PoSRandomness,
    block_timestamp: BlockTimestamp,
    block_height: BlockHeight,
    get_ancestor: G,
    sig_aux_data_provider: &mut AuxP,
) -> Result<(PoSData, BlockReward), ConsensusCreationError>
where
    G: Fn(&BlockIndex, BlockHeight) -> Result<GenBlockIndex, crate::ChainstateError>,
{
    let reward_destination = Destination::PublicKey(pos_input_data.stake_public_key());

    let kernel_output =
        vec![TxOutput::ProduceBlockFromStake(reward_destination, pos_input_data.pool_id())];

    let block_reward_transactable = BlockRewardTransactable::new(
        Some(pos_input_data.kernel_inputs()),
        Some(&kernel_output),
        None,
    );

    let sighash = signature_hash(
        SigHashType::default(),
        &block_reward_transactable,
        &pos_input_data.kernel_input_utxos().iter().map(Some).collect::<Vec<_>>(),
        0,
    )
    .map_err(|_| ConsensusPoSError::FailedToSignKernel)?;

    let signature = sign_public_key_spending(
        pos_input_data.stake_private_key(),
        &pos_input_data.stake_public_key(),
        &sighash,
        sig_aux_data_provider,
    )
    .map_err(|_| ConsensusPoSError::FailedToSignKernel)?;

    let input_witness = InputWitness::Standard(StandardInputSignature::new(
        SigHashType::default(),
        signature.encode(),
    ));

    let vrf_data = {
        let transcript = construct_transcript(
            chain_config.epoch_index_from_height(&block_height),
            &sealed_epoch_randomness.value(),
            block_timestamp,
        );

        pos_input_data.vrf_private_key().produce_vrf_data(transcript)
    };

    let target_required = calculate_target_required_from_block_index(
        chain_config,
        pos_status,
        prev_block_index,
        get_ancestor,
    )?;

    let consensus_data = PoSData::new(
        pos_input_data.kernel_inputs().clone(),
        vec![input_witness],
        pos_input_data.pool_id(),
        vrf_data,
        target_required,
    );

    let block_reward = BlockReward::new(kernel_output);

    Ok((consensus_data, block_reward))
}
