use common::{
    chain::OutPoint,
    primitives::{
        id::{hash_encoded_to, DefaultHashAlgoStream},
        H256,
    },
};
use crypto::hash::StreamHasher;

pub fn pool_address_preimage_suffix() -> u32 {
    // arbitrary, we use this to create different values when hashing with no security requirements
    0
}

pub fn delegation_address_preimage_suffix() -> u32 {
    // arbitrary, we use this to create different values when hashing with no security requirements
    1
}

pub fn make_pool_address(input0_outpoint: &OutPoint) -> H256 {
    let mut pool_address_creator = DefaultHashAlgoStream::new();
    hash_encoded_to(&input0_outpoint, &mut pool_address_creator);
    // 0 is arbitrary here, we use this as prefix to use this information again
    hash_encoded_to(&pool_address_preimage_suffix(), &mut pool_address_creator);
    pool_address_creator.finalize().into()
}

pub fn make_delegation_address(input0_outpoint: &OutPoint) -> H256 {
    let mut pool_address_creator = DefaultHashAlgoStream::new();
    hash_encoded_to(&input0_outpoint, &mut pool_address_creator);
    // 1 is arbitrary here, we use this as prefix to use this information again
    hash_encoded_to(
        &delegation_address_preimage_suffix(),
        &mut pool_address_creator,
    );
    pool_address_creator.finalize().into()
}
