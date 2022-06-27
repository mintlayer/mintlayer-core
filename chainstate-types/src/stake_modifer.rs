use common::{
    chain::OutPoint,
    primitives::{
        id::{hash_encoded_to, DefaultHashAlgoStream},
        H256,
    },
};
use serialization::{Decode, Encode};

#[derive(Encode, Decode, Clone)]
pub struct PoSStakeModifier {
    value: H256,
}

impl PoSStakeModifier {
    pub fn new(value: H256) -> Self {
        Self { value }
    }

    pub fn from_new_block(
        prev_stake_modifier: Option<&PoSStakeModifier>,
        current_kernel_outpoint: &OutPoint,
    ) -> Self {
        use crypto::hash::StreamHasher;

        let prev_stake_modifer_val = prev_stake_modifier.unwrap_or(&Self::at_genesis()).value();

        let mut hasher = DefaultHashAlgoStream::new();
        hash_encoded_to(&prev_stake_modifer_val, &mut hasher);
        hash_encoded_to(&current_kernel_outpoint, &mut hasher);
        let hash: H256 = hasher.finalize().into();

        Self::new(hash)
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
