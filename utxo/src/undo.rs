#![allow(unused, dead_code)]

use crate::Utxo;
use common::primitives::BlockHeight;
use serialization::{Decode, Encode};

#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct TxUndo(Vec<Utxo>);

impl TxUndo {
    pub fn new_empty() -> Self {
        Self(vec![])
    }

    pub fn new(utxos: Vec<Utxo>) -> Self {
        Self(utxos)
    }

    pub fn push(&mut self, utxo: Utxo) {
        self.0.push(utxo)
    }

    pub fn append(&mut self, other: &mut TxUndo) {
        self.0.append(&mut other.0)
    }

    pub fn inner(&self) -> &[Utxo] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<Utxo> {
        self.0
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct BlockUndo {
    // determines at what height this undo file belongs to.
    height: BlockHeight,
    undos: Vec<TxUndo>,
}

impl BlockUndo {
    pub fn new(tx_undos: Vec<TxUndo>, height: BlockHeight) -> Self {
        Self {
            height,
            undos: tx_undos,
        }
    }
    pub fn tx_undos(&self) -> &[TxUndo] {
        &self.undos
    }

    pub fn height(&self) -> BlockHeight {
        self.height
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::test_helper::create_utxo;
    use crypto::random::{make_pseudo_rng, Rng};

    #[test]
    fn tx_undo_test() {
        let (utxo0, _) = create_utxo(0);
        let (utxo1, _) = create_utxo(1);
        let mut tx_undo = TxUndo::new(vec![utxo0.clone()]);

        // check push
        tx_undo.push(utxo1.clone());
        assert_eq!(tx_undo.0.len(), 2);

        // check `inner()`
        {
            let inner = tx_undo.inner();
            assert_eq!(&utxo0, &inner[0]);
            assert_eq!(&utxo1, &inner[1]);
        }

        // check `into_inner()`
        {
            let undo_vec = tx_undo.into_inner();
            assert_eq!(&utxo0, &undo_vec[0]);
            assert_eq!(&utxo1, &undo_vec[1]);
        }
    }

    #[test]
    fn block_undo_test() {
        let expected_height = BlockHeight::new(5);
        let (utxo0, _) = create_utxo(0);
        let (utxo1, _) = create_utxo(1);
        let tx_undo0 = TxUndo::new(vec![utxo0, utxo1]);

        let (utxo2, _) = create_utxo(2);
        let (utxo3, _) = create_utxo(3);
        let (utxo4, _) = create_utxo(4);
        let tx_undo1 = TxUndo::new(vec![utxo2, utxo3, utxo4]);

        let blockundo = BlockUndo::new(vec![tx_undo0.clone(), tx_undo1.clone()], expected_height);

        // check `inner()`
        {
            let inner = blockundo.tx_undos();

            assert_eq!(&tx_undo0, &inner[0]);
            assert_eq!(&tx_undo1, &inner[1]);
        }

        // check the height
        assert_eq!(blockundo.height, expected_height);
    }
}
