mod undo;
mod utxo_impl;

pub use undo::*;
pub use utxo_impl::*;

use thiserror::Error;

#[allow(dead_code)]
#[derive(Error, Debug, Eq, PartialEq)]
pub enum Error {
    #[error("Attempted to overwrite an existing utxo")]
    OverwritingUtxo,
    #[error(
        "The utxo was marked FRESH in the child cache, but the utxo exists in the parent cache. This can be considered a fatal error."
    )]
    FreshUtxoAlreadyExists,
    #[error("Attempted to spend a UTXO that's already spent")]
    UtxoAlreadySpent,
    #[error("Attempted to spend a non-existing UTXO")]
    NoUtxoFound,
    #[error(
        "Attempted to consume a cache object that does not have any best block associated with it"
    )]
    CacheWithoutBestBlock,
    #[error("Attempted to get the block height of a UTXO source that is based on the mempool")]
    NoBlockchainHeightFound,
    #[error("Database error: `{0}`")]
    DBError(String),
}
