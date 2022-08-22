#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum Error {
    #[error("Accounting storage error")]
    StorageError,
    #[error("Pool already exists")]
    InvariantErrorPoolAlreadyExists,
    #[error("Attempted to decommission a non-existing pool")]
    AttemptedDecommissionNonexistingPool,
    #[error("Failed to create a delegation because the target pool doesn't exist")]
    DelegationCreationFailedPoolDoesNotExist,
    #[error("Delegate to a non-existing reward address")]
    DelegateToNonexistingRewardAddress,
    #[error("Delegate to a non-existing pool")]
    DelegateToNonexistingPool,
    #[error("Delegation arithmetic error")]
    DelegationBalanceAdditionError,
    #[error("Pool balance arithmetic error")]
    PoolBalanceAdditionError,
}
