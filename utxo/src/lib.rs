mod undo;
mod utxo_impl;

pub use undo::*;
pub use utxo_impl::*;

#[allow(dead_code)]
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    OverwritingUtxo,
    UtxoAlreadyExists,
    UtxoAlreadySpent,
    NoUtxoFound,
    CacheWithoutBestBlock,
    NoBlockchainHeightFound,
    DBError(String),
}
