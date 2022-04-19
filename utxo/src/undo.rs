use crate::Utxo;
use parity_scale_codec::{Decode, Encode};

#[derive(Debug, Eq, PartialEq, Encode, Decode)]
pub struct TxUndo(Vec<Utxo>);

impl From<Vec<Utxo>> for TxUndo {
    fn from(list: Vec<Utxo>) -> Self {
        TxUndo(list)
    }
}

impl TxUndo {
    fn inner(&self) -> &[Utxo] {
        &self.0
    }

    fn into_inner(self) -> Vec<Utxo> {
        self.0
    }
}


#[derive(Debug, Eq, PartialEq, Encode, Decode)]
pub struct BlockUndo(Vec<TxUndo>);

impl From<Vec<TxUndo>> for BlockUndo {
    fn from(list: Vec<TxUndo>) -> Self {
        BlockUndo(list)
    }
}

impl BlockUndo {
    fn inner(&self) -> &[TxUndo] {
        &self.0
    }

    fn into_inner(self) -> Vec<TxUndo> {
        self.0
    }
}