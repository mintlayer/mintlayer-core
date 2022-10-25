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

use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    ops::RangeInclusive,
};

use crate::Utxo;
use common::{
    chain::{OutPointSourceId, Transaction},
    primitives::{Id, H256},
};
use serialization::{Decode, Encode};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum BlockUndoError {
    #[error("Attempted to insert a transaction in undo that already exists: `{0}`")]
    UndoAlreadyExists(Id<Transaction>),
}

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

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct TxUndoWithSources {
    utxos: Vec<Utxo>,
    sources: Vec<OutPointSourceId>,
}

impl TxUndoWithSources {
    pub fn new(utxos: Vec<Utxo>, sources: Vec<OutPointSourceId>) -> Self {
        Self { utxos, sources }
    }

    pub fn utxos(&self) -> &[Utxo] {
        &self.utxos
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct BlockUndo {
    reward_undo: Option<BlockRewardUndo>,
    tx_undos: BTreeMap<Id<Transaction>, TxUndo>,

    // These collections track the dependencies of tx to one another.
    // Only txs that aren't a dependency for others can be taken out.
    // Collections are a mirrored representation of one another. 2 instances are maintained
    // in order to gain log(N) runtime complexity.
    child_parent_dependencies: BTreeSet<(Id<Transaction>, Id<Transaction>)>,
    parent_child_dependencies: BTreeSet<(Id<Transaction>, Id<Transaction>)>,
}

impl BlockUndo {
    pub fn new(
        reward_undo: Option<BlockRewardUndo>,
        tx_undos: BTreeMap<Id<Transaction>, TxUndoWithSources>,
    ) -> Result<Self, BlockUndoError> {
        let mut block_undo = BlockUndo {
            reward_undo,
            ..Default::default()
        };
        tx_undos
            .into_iter()
            .try_for_each(|(tx_id, tx_undo)| block_undo.insert_tx_undo(tx_id, tx_undo))?;
        Ok(block_undo)
    }

    pub fn is_empty(&self) -> bool {
        self.reward_undo.is_none() && self.tx_undos.is_empty()
    }

    pub fn tx_undos(&self) -> &BTreeMap<Id<Transaction>, TxUndo> {
        &self.tx_undos
    }

    pub fn insert_tx_undo(
        &mut self,
        tx_id: Id<Transaction>,
        tx_undo: TxUndoWithSources,
    ) -> Result<(), BlockUndoError> {
        match self.tx_undos.entry(tx_id) {
            Entry::Vacant(e) => e.insert(TxUndo::new(tx_undo.utxos)),
            Entry::Occupied(_) => return Err(BlockUndoError::UndoAlreadyExists(tx_id)),
        };

        tx_undo
            .sources
            .into_iter()
            .filter_map(|source_id| match source_id {
                OutPointSourceId::Transaction(id) => Some(id),
                OutPointSourceId::BlockReward(_) => None,
            })
            .for_each(|source_tx_id| {
                self.child_parent_dependencies.insert((tx_id, source_tx_id));
                self.parent_child_dependencies.insert((source_tx_id, tx_id));
            });

        Ok(())
    }

    fn tx_children_range(
        tx_id: &Id<Transaction>,
    ) -> RangeInclusive<(Id<Transaction>, Id<Transaction>)> {
        let range_start = (*tx_id, Id::<Transaction>::from(H256::zero()));
        let range_end = (*tx_id, Id::<Transaction>::from(H256::repeat_byte(0xFF)));

        range_start..=range_end
    }

    pub fn has_children_of(&self, tx_id: &Id<Transaction>) -> bool {
        // Check if the tx is a dependency for other txs.
        let dependencies_count =
            self.parent_child_dependencies.range(Self::tx_children_range(tx_id)).count();
        dependencies_count != 0
    }

    fn get_parents_of(&self, tx_id: &Id<Transaction>) -> Vec<(Id<Transaction>, Id<Transaction>)> {
        self.child_parent_dependencies
            .range(Self::tx_children_range(tx_id))
            .copied()
            .collect()
    }

    pub fn take_tx_undo(&mut self, tx_id: &Id<Transaction>) -> Option<TxUndo> {
        if !self.has_children_of(tx_id) {
            // If not this tx can be taken and returned.
            // But first, remove itself as a dependency of others.
            let to_remove = self.get_parents_of(tx_id);

            to_remove.iter().for_each(|(id1, id2)| {
                self.child_parent_dependencies.remove(&(*id1, *id2));
                self.parent_child_dependencies.remove(&(*id2, *id1));
            });

            self.tx_undos.remove(tx_id)
        } else {
            None
        }
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

    pub fn combine(&mut self, other: BlockUndo) -> Result<(), BlockUndoError> {
        // combine reward
        if let Some(reward_undo) = other.reward_undo {
            if self.reward_undo.is_none() && !reward_undo.inner().is_empty() {
                self.reward_undo = Some(Default::default());
            }
            reward_undo.0.into_iter().for_each(|u| {
                self.reward_undo.as_mut().expect("must've been already initialized ").0.push(u);
            })
        }

        // combine utxo
        other
            .tx_undos
            .into_iter()
            .try_for_each(|(id, u)| match self.tx_undos.entry(id) {
                Entry::Vacant(e) => {
                    e.insert(u);
                    Ok(())
                }
                Entry::Occupied(_) => Err(BlockUndoError::UndoAlreadyExists(id)),
            })?;

        // combine dependencies
        other.child_parent_dependencies.into_iter().try_for_each(|v| {
            if !self.child_parent_dependencies.insert(v) {
                return Err(BlockUndoError::UndoAlreadyExists(v.0));
            }
            Ok(())
        })?;
        other.parent_child_dependencies.into_iter().try_for_each(|v| {
            if !self.parent_child_dependencies.insert(v) {
                return Err(BlockUndoError::UndoAlreadyExists(v.0));
            }
            Ok(())
        })
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::tests::test_helper::create_utxo;
    use common::primitives::H256;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn tx_undo_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let (utxo0, _) = create_utxo(&mut rng, 0);
        let (utxo1, _) = create_utxo(&mut rng, 1);
        let tx_undo = TxUndo::new(vec![utxo0.clone(), utxo1.clone()]);

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
        let tx_undo0 = TxUndoWithSources::new(vec![utxo0, utxo1], vec![]);
        let tx_0_id: Id<Transaction> = H256::from_low_u64_be(0).into();

        let (utxo2, _) = create_utxo(&mut rng, 2);
        let (utxo3, _) = create_utxo(&mut rng, 3);
        let (utxo4, _) = create_utxo(&mut rng, 4);
        let tx_undo1 = TxUndoWithSources::new(vec![utxo2, utxo3, utxo4], vec![]);
        let tx_1_id: Id<Transaction> = H256::from_low_u64_be(1).into();

        let (utxo5, _) = create_utxo(&mut rng, 5);
        let reward_undo = BlockRewardUndo::new(vec![utxo5]);

        let mut blockundo: BlockUndo = Default::default();
        blockundo.set_block_reward_undo(reward_undo.clone());
        blockundo.insert_tx_undo(tx_0_id, tx_undo0.clone()).unwrap();
        blockundo.insert_tx_undo(tx_1_id, tx_undo1.clone()).unwrap();

        assert_eq!(
            &TxUndo(tx_undo0.utxos),
            blockundo.tx_undos().get(&tx_0_id).unwrap()
        );
        assert_eq!(
            &TxUndo(tx_undo1.utxos),
            blockundo.tx_undos().get(&tx_1_id).unwrap()
        );

        assert_eq!(&reward_undo, blockundo.block_reward_undo().unwrap());
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn dependencies_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let (utxo0, _) = create_utxo(&mut rng, 0);
        let (utxo1, _) = create_utxo(&mut rng, 1);

        let expected_tx_undo0 = TxUndo::new(vec![utxo0.clone(), utxo1.clone()]);
        let tx_undo0 = TxUndoWithSources {
            utxos: vec![utxo0, utxo1],
            sources: vec![],
        };
        let tx_0_id: Id<Transaction> = H256::from_low_u64_be(1).into();

        let (utxo2, _) = create_utxo(&mut rng, 2);
        let (utxo3, _) = create_utxo(&mut rng, 3);
        let (utxo4, _) = create_utxo(&mut rng, 4);

        let expected_tx_undo1 = TxUndo::new(vec![utxo2.clone(), utxo3.clone(), utxo4.clone()]);
        let tx_undo1 = TxUndoWithSources {
            utxos: vec![utxo2, utxo3, utxo4],
            sources: vec![OutPointSourceId::Transaction(tx_0_id)],
        };
        let tx_1_id: Id<Transaction> = H256::from_low_u64_be(2).into();

        let mut blockundo: BlockUndo = Default::default();
        blockundo.insert_tx_undo(tx_0_id, tx_undo0).unwrap();
        blockundo.insert_tx_undo(tx_1_id, tx_undo1).unwrap();

        assert!(blockundo.take_tx_undo(&tx_0_id).is_none());
        assert_eq!(blockundo.take_tx_undo(&tx_1_id).unwrap(), expected_tx_undo1);
        assert_eq!(blockundo.take_tx_undo(&tx_0_id).unwrap(), expected_tx_undo0);

        assert!(blockundo.tx_undos.is_empty());
        assert!(blockundo.child_parent_dependencies.is_empty());
        assert!(blockundo.parent_child_dependencies.is_empty());
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn combine_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let (reward_utxo1, _) = create_utxo(&mut rng, 1);
        let (reward_utxo2, _) = create_utxo(&mut rng, 2);

        let (utxo1, _) = create_utxo(&mut rng, 3);
        let tx_id_1: Id<Transaction> = Id::new(H256::random_using(&mut rng));
        let (utxo2, _) = create_utxo(&mut rng, 4);
        let tx_id_2: Id<Transaction> = Id::new(H256::random_using(&mut rng));

        let dep_tx_id_1 = Id::<Transaction>::new(H256::random_using(&mut rng));
        let source_id_1 = OutPointSourceId::Transaction(dep_tx_id_1);
        let dep_tx_id_2 = Id::<Transaction>::new(H256::random_using(&mut rng));
        let source_id_2 = OutPointSourceId::Transaction(dep_tx_id_2);

        let mut block_undo_1 = BlockUndo::new(
            Some(BlockRewardUndo::new(vec![reward_utxo1.clone()])),
            BTreeMap::from([(
                tx_id_1,
                TxUndoWithSources::new(vec![utxo1.clone()], vec![source_id_1]),
            )]),
        )
        .unwrap();

        let block_undo_2 = BlockUndo::new(
            Some(BlockRewardUndo::new(vec![reward_utxo2.clone()])),
            BTreeMap::from([(
                tx_id_2,
                TxUndoWithSources::new(vec![utxo2.clone()], vec![source_id_2]),
            )]),
        )
        .unwrap();

        let expected_block_undo = BlockUndo {
            reward_undo: Some(BlockRewardUndo::new(vec![reward_utxo1, reward_utxo2])),
            tx_undos: BTreeMap::from([
                (tx_id_1, TxUndo(vec![utxo1])),
                (tx_id_2, TxUndo(vec![utxo2])),
            ]),
            parent_child_dependencies: BTreeSet::from([
                (dep_tx_id_1, tx_id_1),
                (dep_tx_id_2, tx_id_2),
            ]),
            child_parent_dependencies: BTreeSet::from([
                (tx_id_1, dep_tx_id_1),
                (tx_id_2, dep_tx_id_2),
            ]),
        };

        block_undo_1.combine(block_undo_2).unwrap();
        assert_eq!(block_undo_1, expected_block_undo);
    }
}
