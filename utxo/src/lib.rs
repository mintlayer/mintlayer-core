mod utxo_impl;

pub use utxo_impl::*;

#[allow(dead_code)]
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    OverwritingUtxo,
    UtxoAlreadyExists,
    DBError(String),
}
