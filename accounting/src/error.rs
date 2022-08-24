#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum Error {
    #[error("Accounting storage error")]
    StorageError(#[from] chainstate_types::storage_result::Error),
    #[error("Pool already exists")]
    InvariantErrorPoolAlreadyExists,
    #[error("Attempted to decommission a non-existing pool")]
    AttemptedDecommissionNonexistingPool,
    #[error("Failed to create a delegation because the target pool doesn't exist")]
    DelegationCreationFailedPoolDoesNotExist,
    #[error("Delegate to a non-existing reward address")]
    DelegateToNonexistingAddress,
    #[error("Delegate to a non-existing pool")]
    DelegateToNonexistingPool,
    #[error("Delegation arithmetic error")]
    DelegationBalanceAdditionError,
    #[error("Pool balance arithmetic error")]
    PoolBalanceAdditionError,
    #[error("Delegation shares arithmetic error")]
    DelegationSharesAdditionError,
    #[error("Pool creation undo failed; pool cannot be found")]
    InvariantErrorPoolCreationReversalFailedNotFound,
    #[error("Pledge amount has changed while reversal being done")]
    InvariantErrorPoolCreationReversalFailedAmountChanged,
    #[error("Undo failed as decommission pool is still in storage")]
    InvariantErrorDecommissionUndoFailedAlreadyExists,
    #[error("Reversal of delegation address creation failed; not found")]
    InvariantErrorDelegationAddressUndoFailedNotFound,
    #[error("Reversal of delegation address creation failed; data changed")]
    InvariantErrorDelegationAddressUndoFailedDataConflict,
    #[error("Delegation balance arithmetic undo error")]
    InvariantErrorDelegationBalanceAdditionUndoError,
    #[error("Pool balance arithmetic undo error")]
    InvariantErrorPoolBalanceAdditionUndoError,
    #[error("Delegation shares arithmetic undo error")]
    InvariantErrorDelegationSharesAdditionUndoError,
}
