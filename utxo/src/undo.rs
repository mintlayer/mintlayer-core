// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::Utxo;
use serialization::{Decode, Encode};

#[derive(Default, Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct BlockRewardUndo(Vec<Utxo>);

impl BlockRewardUndo {
    pub fn new(utxos: Vec<Utxo>) -> Self {
        Self(utxos)
    }

    pub fn inner(&self) -> &[Utxo] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<Utxo> {
        self.0
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Encode, Decode)]
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

#[derive(Default, Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct BlockUndo {
    reward_undo: Option<BlockRewardUndo>,
    tx_undos: Vec<TxUndo>,
}

impl BlockUndo {
    pub fn new(reward_undo: Option<BlockRewardUndo>, tx_undos: Vec<TxUndo>) -> Self {
        Self {
            tx_undos,
            reward_undo,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.reward_undo.is_none() && self.tx_undos.is_empty()
    }

    pub fn tx_undos(&self) -> &[TxUndo] {
        &self.tx_undos
    }

    pub fn push_tx_undo(&mut self, tx_undo: TxUndo) {
        self.tx_undos.push(tx_undo);
    }

    pub fn pop_tx_undo(&mut self) -> Option<TxUndo> {
        self.tx_undos.pop()
    }

    pub fn block_reward_undo(&self) -> Option<&BlockRewardUndo> {
        self.reward_undo.as_ref()
    }

    pub fn set_block_reward_undo(&mut self, reward_undo: BlockRewardUndo) {
        debug_assert!(self.reward_undo.is_none());
        self.reward_undo = Some(reward_undo);
    }

    pub fn take_block_reward_undo(&mut self) -> Option<BlockRewardUndo> {
        self.reward_undo.take()
    }

    pub fn append(&mut self, other: BlockUndo) {
        if let Some(reward_undo) = other.reward_undo {
            if self.reward_undo.is_none() && !reward_undo.inner().is_empty() {
                self.reward_undo = Some(Default::default());
            }
            reward_undo.0.into_iter().for_each(|u| {
                self.reward_undo.as_mut().expect("must've been already initialized ").0.push(u);
            })
        }
        other.tx_undos.into_iter().for_each(|u| self.push_tx_undo(u));
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::tests::test_helper::create_utxo;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn tx_undo_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let (utxo0, _) = create_utxo(&mut rng, 0);
        let (utxo1, _) = create_utxo(&mut rng, 1);
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

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn block_undo_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let (utxo0, _) = create_utxo(&mut rng, 0);
        let (utxo1, _) = create_utxo(&mut rng, 1);
        let tx_undo0 = TxUndo::new(vec![utxo0, utxo1]);

        let (utxo2, _) = create_utxo(&mut rng, 2);
        let (utxo3, _) = create_utxo(&mut rng, 3);
        let (utxo4, _) = create_utxo(&mut rng, 4);
        let tx_undo1 = TxUndo::new(vec![utxo2, utxo3, utxo4]);

        let (utxo5, _) = create_utxo(&mut rng, 5);
        let reward_undo = BlockRewardUndo::new(vec![utxo5]);

        let blockundo = BlockUndo::new(
            Some(reward_undo.clone()),
            vec![tx_undo0.clone(), tx_undo1.clone()],
        );

        // check `inner()`
        let inner = blockundo.tx_undos();

        assert_eq!(&tx_undo0, &inner[0]);
        assert_eq!(&tx_undo1, &inner[1]);

        assert_eq!(&reward_undo, blockundo.block_reward_undo().unwrap());
    }
}
