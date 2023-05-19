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

use chainstate_types::pos_randomness::PoSRandomness;
use common::{
    chain::block::timestamp::BlockTimestamp,
    chain::{config::EpochIndex, PoolId, TxInput, TxOutput},
    primitives::Amount,
};
use crypto::{
    key::{PrivateKey, PublicKey},
    vrf::{VRFPrivateKey, VRFPublicKey},
};
use serialization::{Decode, Encode};

pub use crate::{
    error::ConsensusVerificationError,
    pos::{
        block_sig::BlockSignatureError, check_pos_hash, error::ConsensusPoSError,
        kernel::get_kernel_output, stake, target::calculate_target_required,
        target::calculate_target_required_from_block_index, StakeResult,
    },
    pow::{calculate_work_required, check_proof_of_work, mine, ConsensusPoWError, MiningResult},
    validator::validate_consensus,
};

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

/// Input needed to finalize PoS consensus data
///
/// This struct is an internal data structure that will be created by
/// `blockprod`, and will be used when finalizing Proof-of-Stake consensus
/// data (see ConsensusData::PoS for more info) during PoS block creation.
#[derive(Debug, Clone, Encode, Decode)]
pub struct PoSFinalizeBlockInputData {
    /// The private key of the staker
    stake_private_key: PrivateKey,
    /// The VRF private key (i.e used for sealed epoch data)
    vrf_private_key: VRFPrivateKey,
    /// The epoch index of the height of the new block
    epoch_index: EpochIndex,
    /// The sealed epoch randomness (i.e used in producing VRF data)
    sealed_epoch_randomness: PoSRandomness,
    /// The block timestamp of the previous block
    previous_block_timestamp: BlockTimestamp,
    /// The maximum timestamp to try and staking with
    max_block_timestamp: BlockTimestamp,
    /// The current pool balance of the stake pool
    pool_balance: Amount,
}

impl PoSFinalizeBlockInputData {
    pub fn new(
        stake_private_key: PrivateKey,
        vrf_private_key: VRFPrivateKey,
        epoch_index: EpochIndex,
        sealed_epoch_randomness: PoSRandomness,
        previous_block_timestamp: BlockTimestamp,
        max_block_timestamp: BlockTimestamp,
        pool_balance: Amount,
    ) -> Self {
        Self {
            stake_private_key,
            vrf_private_key,
            epoch_index,
            sealed_epoch_randomness,
            previous_block_timestamp,
            max_block_timestamp,
            pool_balance,
        }
    }

    pub fn epoch_index(&self) -> EpochIndex {
        self.epoch_index
    }

    pub fn max_block_timestamp(&self) -> BlockTimestamp {
        self.max_block_timestamp
    }

    pub fn pool_balance(&self) -> Amount {
        self.pool_balance
    }

    pub fn previous_block_timestamp(&self) -> BlockTimestamp {
        self.previous_block_timestamp
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
}
