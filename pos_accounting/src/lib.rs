use common::primitives::Id;

pub mod error;
pub mod pool;
pub mod storage;

#[derive(Default, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Pool;
type PoolId = Id<Pool>;

#[derive(Default, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Delegation;
type DelegationId = Id<Delegation>;
