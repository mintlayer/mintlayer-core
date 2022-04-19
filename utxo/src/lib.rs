mod utxo_impl;
mod undo;

pub use utxo_impl::*;
pub use undo::*;

#[allow(dead_code)]
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    OverwritingUtxo,
    UtxoAlreadyExists,
    CacheWithoutBestBlock,
    NoBlockchainHeightFound,
    DBError(String),
}
