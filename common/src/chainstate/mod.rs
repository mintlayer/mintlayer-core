#[cfg(test)]
mod test;
pub mod utxo;

#[allow(dead_code)]
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    OverwritingUtxo,
    UtxoAlreadyExists,
    DBError(String),
}
