use common::{
    chain::OutPoint,
    primitives::id::{hash_encoded_to, DefaultHashAlgoStream},
};
use crypto::hash::StreamHasher;

use crate::{DelegationId, PoolId};

pub fn pool_id_preimage_suffix() -> u32 {
    // arbitrary, we use this to create different values when hashing with no security requirements
    0
}

pub fn delegation_id_preimage_suffix() -> u32 {
    // arbitrary, we use this to create different values when hashing with no security requirements
    1
}

pub fn make_pool_id(input0_outpoint: &OutPoint) -> PoolId {
    let mut hasher = DefaultHashAlgoStream::new();
    hash_encoded_to(&input0_outpoint, &mut hasher);
    // 0 is arbitrary here, we use this as prefix to use this information again
    hash_encoded_to(&pool_id_preimage_suffix(), &mut hasher);
    PoolId::new(hasher.finalize().into())
}

pub fn make_delegation_id(input0_outpoint: &OutPoint) -> DelegationId {
    let mut hasher = DefaultHashAlgoStream::new();
    hash_encoded_to(&input0_outpoint, &mut hasher);
    // 1 is arbitrary here, we use this as prefix to use this information again
    hash_encoded_to(&delegation_id_preimage_suffix(), &mut hasher);
    DelegationId::new(hasher.finalize().into())
}
