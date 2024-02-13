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

use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};

use crate::Utxo;
use common::{
    chain::{OutPointSourceId, Transaction},
    primitives::Id,
};
use serialization::{Decode, Encode};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum UtxosBlockUndoError {
    #[error("Attempted to insert a transaction in undo that already exists: `{0}`")]
    UndoAlreadyExists(Id<Transaction>),
    #[error("Attempted to insert a reward in undo that already exists")]
    UndoAlreadyExistsForReward,
    #[error("Trying to take TxUndo for a tx `{0}` with a dependency")]
    TxUndoWithDependency(Id<Transaction>),
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct UtxosBlockRewardUndo(Vec<Utxo>);

impl UtxosBlockRewardUndo {
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

// This collection represents all utxos that were spent in a transaction.
// The size of the collection equals to number of inputs, so in case an inputs spends from an account
// it's represented a None
#[derive(Default, Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct UtxosTxUndo(Vec<Option<Utxo>>);

impl UtxosTxUndo {
    pub fn new(utxos: Vec<Option<Utxo>>) -> Self {
        Self(utxos)
    }

    pub fn inner(&self) -> &[Option<Utxo>] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<Option<Utxo>> {
        self.0
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct UtxosTxUndoWithSources {
    utxos: UtxosTxUndo,
    sources: Vec<OutPointSourceId>,
}

impl UtxosTxUndoWithSources {
    pub fn new(utxos: Vec<Option<Utxo>>, sources: Vec<OutPointSourceId>) -> Self {
        Self {
            utxos: UtxosTxUndo::new(utxos),
            sources,
        }
    }

    pub fn utxos(&self) -> &[Option<Utxo>] {
        self.utxos.inner()
    }

    pub fn consume(self) -> (UtxosTxUndo, Vec<OutPointSourceId>) {
        (self.utxos, self.sources)
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct UtxosBlockUndo {
    reward_undo: Option<UtxosBlockRewardUndo>,
    tx_undos: BTreeMap<Id<Transaction>, UtxosTxUndo>,

    // These collections track the dependencies of tx to one another.
    // Only txs that aren't a dependency for others can be taken out.
    // Collections are a mirrored representation of one another. 2 instances are maintained
    // in order to gain log(N) runtime complexity.
    child_parent_dependencies: BTreeSet<(Id<Transaction>, Id<Transaction>)>,
    parent_child_dependencies: BTreeSet<(Id<Transaction>, Id<Transaction>)>,
}

// FIXME: clean up the methods
impl UtxosBlockUndo {
    pub fn new(
        reward_undo: Option<UtxosBlockRewardUndo>,
        tx_undos: BTreeMap<Id<Transaction>, UtxosTxUndoWithSources>,
    ) -> Result<Self, UtxosBlockUndoError> {
        let mut block_undo = UtxosBlockUndo {
            reward_undo,
            tx_undos: Default::default(),
            child_parent_dependencies: Default::default(),
            parent_child_dependencies: Default::default(),
        };
        tx_undos
            .into_iter()
            .try_for_each(|(tx_id, tx_undo)| block_undo.insert_tx_undo(tx_id, tx_undo))?;
        Ok(block_undo)
    }

    pub fn from_data(
        reward_undo: Option<UtxosBlockRewardUndo>,
        tx_undos: BTreeMap<Id<Transaction>, UtxosTxUndo>,
        child_parent_dependencies: BTreeSet<(Id<Transaction>, Id<Transaction>)>,
        parent_child_dependencies: BTreeSet<(Id<Transaction>, Id<Transaction>)>,
    ) -> Self {
        Self {
            reward_undo,
            tx_undos,
            child_parent_dependencies,
            parent_child_dependencies,
        }
    }

    pub fn consume(
        self,
    ) -> (
        Option<UtxosBlockRewardUndo>,
        BTreeMap<Id<Transaction>, UtxosTxUndo>,
        BTreeSet<(Id<Transaction>, Id<Transaction>)>,
        BTreeSet<(Id<Transaction>, Id<Transaction>)>,
    ) {
        (
            self.reward_undo,
            self.tx_undos,
            self.child_parent_dependencies,
            self.parent_child_dependencies,
        )
    }

    pub fn tx_undos(&self) -> &BTreeMap<Id<Transaction>, UtxosTxUndo> {
        &self.tx_undos
    }

    pub fn insert_tx_undo(
        &mut self,
        tx_id: Id<Transaction>,
        tx_undo: UtxosTxUndoWithSources,
    ) -> Result<(), UtxosBlockUndoError> {
        match self.tx_undos.entry(tx_id) {
            Entry::Vacant(e) => e.insert(tx_undo.utxos),
            Entry::Occupied(_) => return Err(UtxosBlockUndoError::UndoAlreadyExists(tx_id)),
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

        let mut blockundo: UtxosBlockUndo = Default::default();
        blockundo.insert_tx_undo(tx_0_id, tx_undo0.clone()).unwrap();
        blockundo.insert_tx_undo(tx_1_id, tx_undo1.clone()).unwrap();

        assert_eq!(&tx_undo0.utxos, blockundo.tx_undos.get(&tx_0_id).unwrap());
        assert_eq!(&tx_undo1.utxos, blockundo.tx_undos.get(&tx_1_id).unwrap());
    }
}
