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

use crate::{pos::error::ConsensusPoSError, ConsensusCreationError};
use common::chain::{
    block::{BlockReward, BlockRewardTransactable},
    signature::{
        inputsig::{
            authorize_pubkey_spend::sign_pubkey_spending,
            standard_signature::StandardInputSignature, InputWitness,
        },
        sighash::{sighashtype::SigHashType, signature_hash},
    },
    Destination, PoolId, TxInput, TxOutput,
};
use crypto::{
    key::{PrivateKey, PublicKey},
    vrf::VRFPrivateKey,
};
use randomness::{CryptoRng, Rng};
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

/// The part of PoSData that can be calculated before the parent or a timestamp of a
/// new block is known.
#[derive(Debug, Clone)]
pub struct PoSPartialConsensusData {
    /// Inputs for block reward
    pub kernel_inputs: Vec<TxInput>,
    pub kernel_witness: Vec<InputWitness>,

    /// Pool id.
    pub pool_id: PoolId,
}

pub fn generate_pos_consensus_data_and_reward<R: Rng + CryptoRng>(
    input_data: PoSGenerateBlockInputData,
    rng: R,
) -> Result<(PoSPartialConsensusData, BlockReward), ConsensusCreationError> {
    let stake_public_key = input_data.stake_public_key();
    let reward_destination = Destination::PublicKey(stake_public_key.clone());

    let kernel_output =
        vec![TxOutput::ProduceBlockFromStake(reward_destination, input_data.pool_id)];

    let block_reward_transactable =
        BlockRewardTransactable::new(Some(&input_data.kernel_inputs), Some(&kernel_output), None);

    let sighash = signature_hash(
        SigHashType::default(),
        &block_reward_transactable,
        &input_data.kernel_input_utxos.iter().map(Some).collect::<Vec<_>>(),
        0,
    )
    .map_err(|_| ConsensusPoSError::FailedToSignKernel)?;

    let signature = sign_pubkey_spending(
        &input_data.stake_private_key,
        &stake_public_key,
        &sighash,
        rng,
    )
    .map_err(|_| ConsensusPoSError::FailedToSignKernel)?;

    let input_witness = InputWitness::Standard(StandardInputSignature::new(
        SigHashType::default(),
        signature.encode(),
    ));

    let block_reward = BlockReward::new(kernel_output);

    Ok((
        PoSPartialConsensusData {
            kernel_inputs: input_data.kernel_inputs,
            kernel_witness: vec![input_witness],
            pool_id: input_data.pool_id,
        },
        block_reward,
    ))
}
