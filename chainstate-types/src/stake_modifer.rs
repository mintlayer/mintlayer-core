use common::{
    chain::{
        block::{consensus_data::PoSData, BlockHeader},
        Block, ChainConfig, TxOutput,
    },
    primitives::{
        id::{hash_encoded_to, DefaultHashAlgoStream},
        Id, Idable, H256,
    },
};
use serialization::{Decode, Encode};
use thiserror::Error;

use crate::{
    block_index::BlockIndex,
    vrf_tools::{verify_vrf_and_get_vrf_output, ProofOfStakeVRFError},
};

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum StakeModifierError {
    #[error("Attempted to use a non-locked stake as stake kernel in block {0}")]
    InvalidOutputPurposeInStakeKernel(Id<Block>),
    #[error("Failed to verify VRF data with error: {0}")]
    VRFDataVerificationFailed(ProofOfStakeVRFError),
}

#[derive(Debug, Encode, Decode, Clone)]
pub struct PoSStakeModifier {
    value: H256,
}

impl PoSStakeModifier {
    pub fn new(value: H256) -> Self {
        Self { value }
    }

    pub fn from_new_block(
        chain_config: &ChainConfig,
        previous_randomness: Option<&PoSStakeModifier>,
        prev_block_index: &BlockIndex,
        header: &BlockHeader,
        kernel_output: &TxOutput,
        pos_data: &PoSData,
    ) -> Result<Self, StakeModifierError> {
        use crypto::hash::StreamHasher;

        let prev_stake_modifer = previous_randomness.cloned().unwrap_or(Self::at_genesis());
        let prev_stake_modifer_val = prev_stake_modifer.value();

        let epoch_index =
            chain_config.epoch_index_from_height(&prev_block_index.block_height().next_height());

        let pool_data = match kernel_output.purpose() {
            common::chain::OutputPurpose::Transfer(_)
            | common::chain::OutputPurpose::LockThenTransfer(_, _) => {
                // only pool outputs can be staked
                return Err(StakeModifierError::InvalidOutputPurposeInStakeKernel(
                    header.get_id(),
                ));
            }

            common::chain::OutputPurpose::StakePool(d) => &**d,
        };

        let hash_pos: H256 = verify_vrf_and_get_vrf_output(
            epoch_index,
            &prev_stake_modifer_val,
            pos_data.vrf_data(),
            pool_data.vrf_public_key(),
            header,
        )
        .map_err(StakeModifierError::VRFDataVerificationFailed)?;

        let mut hasher = DefaultHashAlgoStream::new();
        hash_encoded_to(&prev_stake_modifer_val, &mut hasher);
        hash_encoded_to(&hash_pos, &mut hasher);
        let hash: H256 = hasher.finalize().into();

        Ok(Self::new(hash))
    }

    /// stake modifier at genesis
    fn at_genesis() -> Self {
        Self {
            value: H256::zero(),
        }
    }

    pub fn value(&self) -> H256 {
        self.value
    }
}
