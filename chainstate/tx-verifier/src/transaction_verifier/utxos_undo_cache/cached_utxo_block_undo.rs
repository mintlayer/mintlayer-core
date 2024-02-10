// Copyright (c) 2024 RBB S.r.l
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

use crate::transaction_verifier::CachedOperation;
use common::{
    chain::{OutPointSourceId, Transaction},
    primitives::{Id, H256},
};
use utils::ensure;
use utxo::{
    UtxosBlockRewardUndo, UtxosBlockUndo, UtxosBlockUndoError, UtxosTxUndo, UtxosTxUndoWithSources,
};

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct CachedUtxosBlockUndo {
    reward_undo: Option<CachedOperation<UtxosBlockRewardUndo>>,
    tx_undos: BTreeMap<Id<Transaction>, CachedOperation<UtxosTxUndo>>,

    // These collections track the dependencies of tx to one another.
    // Only txs that aren't a dependency for others can be taken out.
    // Collections are a mirrored representation of one another. 2 instances are maintained
    // in order to gain log(N) runtime complexity.
    child_parent_dependencies: BTreeMap<Id<Transaction>, CachedOperation<Id<Transaction>>>,
    parent_child_dependencies: BTreeMap<Id<Transaction>, CachedOperation<Id<Transaction>>>,
}

impl CachedUtxosBlockUndo {
    pub fn new(
        reward_undo: Option<UtxosBlockRewardUndo>,
        tx_undos: BTreeMap<Id<Transaction>, UtxosTxUndoWithSources>,
    ) -> Result<Self, UtxosBlockUndoError> {
        todo!()
    }
    //pub fn new(
    //    reward_undo: Option<UtxosBlockRewardUndo>,
    //    tx_undos: BTreeMap<Id<Transaction>, UtxosTxUndoWithSources>,
    //) -> Result<Self, UtxosBlockUndoError> {
    //    let mut block_undo = CachedUtxosBlockUndo {
    //        reward_undo,
    //        tx_undos: Default::default(),
    //        child_parent_dependencies: Default::default(),
    //        parent_child_dependencies: Default::default(),
    //    };
    //    tx_undos
    //        .into_iter()
    //        .try_for_each(|(tx_id, tx_undo)| block_undo.insert_tx_undo(tx_id, tx_undo))?;
    //    Ok(block_undo)
    //}

    pub fn from_utxo_block_undo(undo: UtxosBlockUndo) -> Result<Self, UtxosBlockUndoError> {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        self.reward_undo.is_none() && self.tx_undos.is_empty()
    }

    //pub fn tx_undos(&self) -> &BTreeMap<Id<Transaction>, UtxosTxUndo> {
    //    &self.tx_undos
    //}

    pub fn consume(self) -> UtxosBlockUndo {
        todo!()
    }

    pub fn insert_tx_undo(
        &mut self,
        tx_id: Id<Transaction>,
        tx_undo: UtxosTxUndoWithSources,
    ) -> Result<(), UtxosBlockUndoError> {
        let (utxos, sources) = tx_undo.consume();

        match self.tx_undos.entry(tx_id) {
            Entry::Vacant(e) => e.insert(CachedOperation::Write(utxos)),
            Entry::Occupied(e) => return Err(UtxosBlockUndoError::UndoAlreadyExists(tx_id)),
        };

        sources
            .into_iter()
            .filter_map(|source_id| match source_id {
                OutPointSourceId::Transaction(id) => Some(id),
                OutPointSourceId::BlockReward(_) => None,
            })
            .for_each(|source_tx_id| {
                self.child_parent_dependencies
                    .insert(tx_id, CachedOperation::Write(source_tx_id));
                self.parent_child_dependencies
                    .insert(source_tx_id, CachedOperation::Write(tx_id));
            });

        Ok(())
    }

    pub fn has_children_of(&self, tx_id: &Id<Transaction>) -> bool {
        // Check if the tx is a dependency for other txs.
        self.parent_child_dependencies
            .iter()
            .filter(|(id, _)| *id == tx_id)
            .any(|(_, child)| child.get().is_some())
    }

    fn get_parents_of(&self, tx_id: &Id<Transaction>) -> Vec<(Id<Transaction>, Id<Transaction>)> {
        self.child_parent_dependencies
            .iter()
            .filter(|(child, _)| *child == tx_id)
            .filter_map(|(child, parent)| parent.get().map(|p| (*child, *p)))
            .collect()
    }

    pub fn take_tx_undo(
        &mut self,
        tx_id: &Id<Transaction>,
    ) -> Result<Option<UtxosTxUndo>, UtxosBlockUndoError> {
        if !self.has_children_of(tx_id) {
            // If not this tx can be taken and returned.
            // But first, remove itself as a dependency of others.
            let to_remove = self.get_parents_of(tx_id);

            to_remove.iter().for_each(|(id1, id2)| {
                self.child_parent_dependencies.insert(*id1, CachedOperation::Erase);
                self.parent_child_dependencies.insert(*id2, CachedOperation::Erase);
            });

            let res = self
                .tx_undos
                .insert(*tx_id, CachedOperation::Erase)
                .map(|op| op.take())
                .flatten();
            Ok(res)
        } else {
            Err(UtxosBlockUndoError::TxUndoWithDependency(*tx_id))
        }
    }

    //pub fn block_reward_undo(&self) -> Option<&UtxosBlockRewardUndo> {
    //    self.reward_undo.as_ref()
    //}

    pub fn set_block_reward_undo(&mut self, reward_undo: UtxosBlockRewardUndo) {
        debug_assert!(self.reward_undo.is_none());
        self.reward_undo = Some(CachedOperation::Write(reward_undo));
    }

    pub fn take_block_reward_undo(&mut self) -> Option<UtxosBlockRewardUndo> {
        self.reward_undo.take().map(|op| op.take()).flatten()
    }

    pub fn combine(&mut self, other: Self) -> Result<(), UtxosBlockUndoError> {
        // combine reward
        match (&mut self.reward_undo, other.reward_undo) {
            (None, None) | (Some(_), None) => { /* do nothing */ }
            (None, Some(reward_undo)) => {
                self.reward_undo = Some(reward_undo);
            }
            (Some(_), Some(_)) => panic!(),
        }

        // combine utxos
        other.tx_undos.into_iter().try_for_each(|(id, u)| {
            if self.tx_undos.insert(id, u).is_some() {
                return Err(UtxosBlockUndoError::UndoAlreadyExists(id));
            }
            Ok(())
        })?;

        // combine dependencies
        other.child_parent_dependencies.into_iter().try_for_each(|(k, v)| {
            if self.child_parent_dependencies.insert(k, v).is_some() {
                return Err(UtxosBlockUndoError::UndoAlreadyExists(k));
            }
            Ok(())
        })?;
        other.parent_child_dependencies.into_iter().try_for_each(|(k, v)| {
            if self.parent_child_dependencies.insert(k, v).is_some() {
                return Err(UtxosBlockUndoError::UndoAlreadyExists(k));
            }
            Ok(())
        })
    }
}

/*
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
        let tx_undo = UtxosTxUndo::new(vec![Some(utxo0.clone()), None, Some(utxo1.clone())]);

        // check `inner()`
        let inner = tx_undo.inner();
        assert_eq!(Some(utxo0.clone()), inner[0]);
        assert_eq!(None, inner[1]);
        assert_eq!(Some(utxo1.clone()), inner[2]);

        // check `into_inner()`
        let undo_vec = tx_undo.into_inner();
        assert_eq!(Some(utxo0), undo_vec[0]);
        assert_eq!(None, undo_vec[1]);
        assert_eq!(Some(utxo1), undo_vec[2]);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn block_undo_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let (utxo0, _) = create_utxo(&mut rng, 0);
        let (utxo1, _) = create_utxo(&mut rng, 1);
        let tx_undo0 = UtxosTxUndoWithSources::new(vec![Some(utxo0), None, Some(utxo1)], vec![]);
        let tx_0_id: Id<Transaction> = H256::from_low_u64_be(0).into();

        let (utxo2, _) = create_utxo(&mut rng, 2);
        let (utxo3, _) = create_utxo(&mut rng, 3);
        let (utxo4, _) = create_utxo(&mut rng, 4);
        let tx_undo1 =
            UtxosTxUndoWithSources::new(vec![Some(utxo2), None, Some(utxo3), Some(utxo4)], vec![]);
        let tx_1_id: Id<Transaction> = H256::from_low_u64_be(1).into();

        let (utxo5, _) = create_utxo(&mut rng, 5);
        let reward_undo = UtxosBlockRewardUndo::new(vec![utxo5]);

        let mut blockundo: CachedUtxosBlockUndo = Default::default();
        blockundo.set_block_reward_undo(reward_undo.clone());
        blockundo.insert_tx_undo(tx_0_id, tx_undo0.clone()).unwrap();
        blockundo.insert_tx_undo(tx_1_id, tx_undo1.clone()).unwrap();

        assert_eq!(&tx_undo0.utxos, blockundo.tx_undos().get(&tx_0_id).unwrap());
        assert_eq!(&tx_undo1.utxos, blockundo.tx_undos().get(&tx_1_id).unwrap());

        assert_eq!(&reward_undo, blockundo.block_reward_undo().unwrap());
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn dependencies_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let (utxo0, _) = create_utxo(&mut rng, 0);
        let (utxo1, _) = create_utxo(&mut rng, 1);

        let expected_tx_undo0 =
            UtxosTxUndo::new(vec![Some(utxo0.clone()), None, Some(utxo1.clone())]);
        let tx_undo0 = UtxosTxUndoWithSources {
            utxos: UtxosTxUndo::new(vec![Some(utxo0), None, Some(utxo1)]),
            sources: vec![],
        };
        let tx_0_id: Id<Transaction> = H256::from_low_u64_be(1).into();

        let (utxo2, _) = create_utxo(&mut rng, 2);
        let (utxo3, _) = create_utxo(&mut rng, 3);
        let (utxo4, _) = create_utxo(&mut rng, 4);

        let expected_tx_undo1 = UtxosTxUndo::new(vec![
            Some(utxo2.clone()),
            None,
            Some(utxo3.clone()),
            Some(utxo4.clone()),
        ]);
        let tx_undo1 = UtxosTxUndoWithSources {
            utxos: UtxosTxUndo::new(vec![Some(utxo2), None, Some(utxo3), Some(utxo4)]),
            sources: vec![OutPointSourceId::Transaction(tx_0_id)],
        };
        let tx_1_id: Id<Transaction> = H256::from_low_u64_be(2).into();

        let mut blockundo: CachedUtxosBlockUndo = Default::default();
        blockundo.insert_tx_undo(tx_0_id, tx_undo0).unwrap();
        blockundo.insert_tx_undo(tx_1_id, tx_undo1).unwrap();

        assert_eq!(
            blockundo.take_tx_undo(&tx_0_id).unwrap_err(),
            UtxosBlockUndoError::TxUndoWithDependency(tx_0_id)
        );
        assert_eq!(
            blockundo.take_tx_undo(&tx_1_id).unwrap(),
            Some(expected_tx_undo1)
        );
        assert_eq!(
            blockundo.take_tx_undo(&tx_0_id).unwrap(),
            Some(expected_tx_undo0)
        );

        assert!(blockundo.tx_undos.is_empty());
        assert!(blockundo.child_parent_dependencies.is_empty());
        assert!(blockundo.parent_child_dependencies.is_empty());
    }
}
*/
