// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen
#![allow(unused)]

use crate::{
    error::{self, P2pError},
    sync::mock_consensus,
};
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
    ops::{Deref, DerefMut},
};

/// Trait which must be implemented for the queued data
///
/// Import queue uses the data ID and it's ancestor's ID to order
/// the incoming data correctly.
pub trait Orderable {
    type Id: Debug + Hash + PartialEq + Eq + Copy + Clone;

    fn get_id(&self) -> &Self::Id;
    fn get_prev_id(&self) -> &Option<Self::Id>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedData<T>(Vec<T>);

impl<T> Deref for QueuedData<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderedData<T>(Vec<Vec<T>>);

impl<T> OrderedData<T> {
    pub fn queue(&mut self, data: T, idx: usize) {
        if self.0.len() > idx {
            self.0[idx].push(data);
        } else {
            self.0.push(vec![data]);
        }
    }
}

impl<T> Deref for OrderedData<T> {
    type Target = Vec<Vec<T>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, PartialEq)]
pub enum ImportQueueState {
    /// Element has been queued
    Queued,

    /// Element resolves a dependency and all elements can be queried
    Resolved,
}

// TODO: implement `Indexable` trait for LRU cache and a hashmap
// TODO: verify that the import queue handles correctly the case where an entry expires
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ImportQueue<T>
where
    T: Orderable,
{
    lookup: HashMap<T::Id, (T::Id, usize)>,
    export: HashMap<T::Id, OrderedData<T>>,
}

impl<T> Default for ImportQueue<T>
where
    T: Orderable + Clone + Debug,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> ImportQueue<T>
where
    T: Orderable + Clone + Debug,
{
    pub fn new() -> Self {
        Self {
            lookup: HashMap::new(),
            export: HashMap::new(),
        }
    }

    /// Return the total number of queued elements in the import queue
    pub fn num_queued(&self) -> usize {
        self.lookup.len()
    }

    /// Return the number of individual chains that the import queue is tracking
    pub fn num_chains(&self) -> usize {
        self.export.len()
    }

	/// Return whether the queue is empty or not
    pub fn is_empty(&self) -> bool {
        self.num_chains() == 0 && self.num_queued() == 0
    }

    /// Check if the queue contains an element
    pub fn contains_key(&self, key: &T::Id) -> bool {
        self.export.contains_key(key) || self.lookup.contains_key(key)
    }

    /// Resolve the depenencies of a data item `id` by requeuing its elements
    fn resolve_deps(&mut self, id: &T::Id) -> error::Result<ImportQueueState> {
        if let Some(exported) = self.export.remove(id) {
            let resolved = QueuedData(exported.0.into_iter().flatten().collect());

            // import all data of the now-resolved descendant and remove all old references
            resolved.0.into_iter().for_each(|descendant| {
                self.lookup.remove(descendant.get_id());
                self.queue(descendant);
            });
        }

        Ok(ImportQueueState::Queued)
    }

    // TODO: verify that duplicate entries are handled correctly

    /// Try to queue element to the import queue and if it resolves a dependency,
    /// return [`ImportQueueState::Resolved`] instead which indicates to the caller
    /// they can now try and fetch all the data from the queue.
    pub fn try_queue(&mut self, data: &T) -> error::Result<ImportQueueState> {
        let prev_id = data.get_prev_id().ok_or(P2pError::InvalidData)?;

        // dependency has been resolved if the export table contains an entry with this
        // id but the lookup table doesn't and the entry's parent is not in the export table
        if self.export.contains_key(data.get_id())
            && !self.lookup.contains_key(&prev_id)
            && !self.export.contains_key(&prev_id)
        {
            return Ok(ImportQueueState::Resolved);
        }

        self.queue(data.clone())
    }

    // TODO: verify that recursion is not possible, write a test case for it?

    /// Add element to the import queue
    pub fn queue(&mut self, data: T) -> error::Result<ImportQueueState> {
        let prev_id = data.get_prev_id().ok_or(P2pError::InvalidData)?;
        let id = *data.get_id();

        match self.export.get_mut(&prev_id) {
            Some(ancestor) => {
                self.lookup.insert(id, (prev_id, 0));
                ancestor.queue(data, 0);
            }
            None => match self.lookup.get(&prev_id) {
                Some(info) => {
                    let (ancestor, idx) = (info.0, info.1 + 1);
                    self.lookup.insert(id, (ancestor, idx));
                    self.export.get_mut(&ancestor).ok_or(P2pError::InvalidData)?.queue(data, idx);
                }
                None => {
                    self.lookup.insert(id, (prev_id, 0));
                    self.export.insert(prev_id, OrderedData(vec![vec![data]]));
                }
            },
        }

        self.resolve_deps(&id)
    }

    /// Get queued descendants
    pub fn drain_with_id(&mut self, data: &T::Id) -> Option<QueuedData<T>> {
        if let Some(exported) = self.export.remove(data) {
            let resolved = QueuedData(exported.0.into_iter().flatten().collect());

            // remove all export and lookup references that are no longer needed
            resolved.0.iter().for_each(|descendant| {
                self.lookup.remove(descendant.get_id()).map_or_else(|| (), |_| ())
            });
            self.lookup.remove(data);

            return Some(resolved);
        }

        None
    }

    /// Get all non-orphan chains from the import queue and clear all unresolved data
    pub fn drain(&mut self) -> Vec<QueuedData<T>> {
        let imported = self
            .export
            .keys()
            .copied()
            .collect::<Vec<T::Id>>()
            .iter()
            .filter_map(|key| self.drain_with_id(key))
            .collect::<Vec<QueuedData<T>>>();

        self.lookup.clear();
        self.export.clear();

        imported
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::mock_consensus::{BlockHeader, BlockId};
    use itertools::Itertools;
    use rand::prelude::SliceRandom;

    #[test]
    fn add_block() {
        let mut q = ImportQueue::new();

        let hdr1 = BlockHeader::new(Some(1337u64));
        let hdr2 = BlockHeader::new(Some(1337u64));

        assert_eq!(q.try_queue(&hdr1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr2), Ok(ImportQueueState::Queued));

        assert_eq!(
            q.export,
            HashMap::from([(1337, OrderedData(vec![vec![hdr1, hdr2]]))])
        );
    }

    #[test]
    fn add_block_v2() {
        let mut q = ImportQueue::new();

        let hdr1 = BlockHeader::new(Some(1337u64));
        let hdr2 = BlockHeader::new(Some(1337u64));

        assert_eq!(q.try_queue(&hdr2), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr1), Ok(ImportQueueState::Queued));
        assert_eq!(
            q.export,
            HashMap::from([(1337, OrderedData(vec![vec![hdr2, hdr1]]))])
        );

        let hdr1_1 = BlockHeader {
            id: 1338u64,
            prev_id: Some(hdr1.id),
        };
        assert_eq!(q.try_queue(&hdr1_1), Ok(ImportQueueState::Queued));
        assert_eq!(
            q.export,
            HashMap::from([(1337, OrderedData(vec![vec![hdr2, hdr1], vec![hdr1_1]]))])
        );

        let hdr1_2 = BlockHeader {
            id: 1339u64,
            prev_id: Some(hdr1.id),
        };
        assert_eq!(q.try_queue(&hdr1_2), Ok(ImportQueueState::Queued));
        assert_eq!(
            q.export,
            HashMap::from([(
                1337,
                OrderedData(vec![vec![hdr2, hdr1], vec![hdr1_1, hdr1_2]])
            )])
        );

        let hdr1_1_1 = BlockHeader {
            id: 1340u64,
            prev_id: Some(hdr1_1.id),
        };
        assert_eq!(q.try_queue(&hdr1_1_1), Ok(ImportQueueState::Queued));
        assert_eq!(
            q.export,
            HashMap::from([(
                1337,
                OrderedData(vec![vec![hdr2, hdr1], vec![hdr1_1, hdr1_2], vec![hdr1_1_1]])
            )])
        );
    }

    #[test]
    fn add_block_v3() {
        let mut q = ImportQueue::new();

        let hdr1 = BlockHeader::new(Some(1337u64));
        let hdr2 = BlockHeader::new(Some(1337u64));
        let hdr1_1 = BlockHeader::new(Some(hdr1.id));
        let hdr1_2 = BlockHeader::new(Some(hdr1.id));
        let hdr1_1_1 = BlockHeader::new(Some(hdr1_1.id));

        assert_eq!(q.try_queue(&hdr1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr2), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr1_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr1_2), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr1_1_1), Ok(ImportQueueState::Queued));

        assert_eq!(
            q.export,
            HashMap::from([(
                1337,
                OrderedData(vec![vec![hdr1, hdr2], vec![hdr1_1, hdr1_2], vec![hdr1_1_1]])
            )])
        );

        let hdr5 = BlockHeader::new(Some(555u64));
        let hdr5_1 = BlockHeader::new(Some(hdr5.id));
        let hdr5_1_1 = BlockHeader::new(Some(hdr5_1.id));
        let hdr5_1_1_1 = BlockHeader::new(Some(hdr5_1_1.id));

        assert_eq!(q.try_queue(&hdr5), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr5_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr5_1_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr5_1_1_1), Ok(ImportQueueState::Queued));

        assert_eq!(
            q.export,
            HashMap::from([
                (
                    555,
                    OrderedData(vec![
                        vec![hdr5],
                        vec![hdr5_1],
                        vec![hdr5_1_1],
                        vec![hdr5_1_1_1]
                    ])
                ),
                (
                    1337,
                    OrderedData(vec![vec![hdr1, hdr2], vec![hdr1_1, hdr1_2], vec![hdr1_1_1]])
                ),
            ])
        );
    }

    #[test]
    fn resolve() {
        let mut q = ImportQueue::new();

        let hdr1 = BlockHeader::new(Some(1337u64));
        let hdr2 = BlockHeader::new(Some(1337u64));
        let hdr1_1 = BlockHeader::new(Some(hdr1.id));
        let hdr1_2 = BlockHeader::new(Some(hdr1.id));
        let hdr1_1_1 = BlockHeader::new(Some(hdr1_1.id));

        assert_eq!(q.try_queue(&hdr1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr2), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr1_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr1_2), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr1_1_1), Ok(ImportQueueState::Queued));

        assert_eq!(
            q.export,
            HashMap::from([(
                1337,
                OrderedData(vec![vec![hdr1, hdr2], vec![hdr1_1, hdr1_2], vec![hdr1_1_1]])
            )])
        );

        let block = BlockHeader {
            id: 1337u64,
            prev_id: Some(1336u64),
        };
        assert_eq!(q.try_queue(&block), Ok(ImportQueueState::Resolved));
        assert_eq!(
            q.drain_with_id(&block.id),
            Some(QueuedData(vec![hdr1, hdr2, hdr1_1, hdr1_2, hdr1_1_1]))
        );
    }

    #[test]
    fn resolve_v2() {
        let mut q = ImportQueue::new();

        let hdr1 = BlockHeader::new(Some(1337u64));
        let hdr2 = BlockHeader::new(Some(1337u64));
        let hdr1_1 = BlockHeader::new(Some(hdr1.id));
        let hdr1_2 = BlockHeader::new(Some(hdr1.id));
        let hdr1_1_1 = BlockHeader::new(Some(hdr1_1.id));

        assert_eq!(q.try_queue(&hdr1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr2), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr1_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr1_2), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr1_1_1), Ok(ImportQueueState::Queued));

        assert_eq!(
            q.export,
            HashMap::from([(
                1337,
                OrderedData(vec![vec![hdr1, hdr2], vec![hdr1_1, hdr1_2], vec![hdr1_1_1]])
            )])
        );

        let hdr5 = BlockHeader::new(Some(555u64));
        let hdr5_1 = BlockHeader::new(Some(hdr5.id));
        let hdr5_1_1 = BlockHeader::new(Some(hdr5_1.id));
        let hdr5_1_1_1 = BlockHeader::new(Some(hdr5_1_1.id));

        assert_eq!(q.try_queue(&hdr5), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr5_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr5_1_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr5_1_1_1), Ok(ImportQueueState::Queued));

        assert_eq!(
            q.export,
            HashMap::from([
                (
                    555,
                    OrderedData(vec![
                        vec![hdr5],
                        vec![hdr5_1],
                        vec![hdr5_1_1],
                        vec![hdr5_1_1_1]
                    ])
                ),
                (
                    1337,
                    OrderedData(vec![vec![hdr1, hdr2], vec![hdr1_1, hdr1_2], vec![hdr1_1_1]])
                ),
            ])
        );

        let block = BlockHeader {
            id: 1337u64,
            prev_id: Some(1336u64),
        };
        assert_eq!(q.try_queue(&block), Ok(ImportQueueState::Resolved));
        assert_eq!(
            q.drain_with_id(&block.id),
            Some(QueuedData(vec![hdr1, hdr2, hdr1_1, hdr1_2, hdr1_1_1])),
        );
        assert_eq!(
            q.export,
            HashMap::from([(
                555,
                OrderedData(vec![
                    vec![hdr5],
                    vec![hdr5_1],
                    vec![hdr5_1_1],
                    vec![hdr5_1_1_1]
                ])
            ),])
        );

        let block = BlockHeader {
            id: 555u64,
            prev_id: Some(444u64),
        };
        assert_eq!(q.try_queue(&block), Ok(ImportQueueState::Resolved));
        assert_eq!(
            q.drain_with_id(&block.id),
            Some(QueuedData(vec![hdr5, hdr5_1, hdr5_1_1, hdr5_1_1_1])),
        );
        assert!(q.lookup.is_empty());
        assert!(q.export.is_empty());
    }

    #[test]
    fn out_of_order_simple() {
        let mut q = ImportQueue::new();

        let hdr1 = BlockHeader::new(Some(1337u64));
        let hdr1_1 = BlockHeader::new(Some(hdr1.id));
        let hdr1_1_1 = BlockHeader::new(Some(hdr1_1.id));

        // queue the blocks in in correct order that even if
        // they create temporary export structures, in the end
        // they are merged together and only one `QueuedData` is returned
        assert_eq!(q.try_queue(&hdr1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr1_1_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr1_1), Ok(ImportQueueState::Queued));

        assert_eq!(
            q.export,
            HashMap::from([(
                1337,
                OrderedData(vec![vec![hdr1], vec![hdr1_1], vec![hdr1_1_1]])
            )])
        );
    }

    #[test]
    fn out_of_order_more_deps() {
        let mut q = ImportQueue::new();

        let hdr1 = BlockHeader::with_id(1, Some(1337u64));
        let hdr1_1 = BlockHeader::with_id(11, Some(hdr1.id));
        let hdr1_1_1 = BlockHeader::with_id(111, Some(hdr1_1.id));
        let hdr2 = BlockHeader::with_id(2, Some(1337u64));
        let hdr1_2 = BlockHeader::with_id(12, Some(hdr1.id));

        // queue the blocks in in correct order that even if
        // they create temporary export structures, in the end
        // they are merged together and only one `QueuedData` is returned
        assert_eq!(q.try_queue(&hdr1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr1_1_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr1_2), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr2), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr1_1), Ok(ImportQueueState::Queued));

        assert_eq!(
            q.export,
            HashMap::from([(
                1337,
                OrderedData(vec![vec![hdr1, hdr2], vec![hdr1_2, hdr1_1], vec![hdr1_1_1]])
            )])
        );
    }

    #[test]
    fn out_of_order_more_deps_exported_while_in_progress() {
        let mut q = ImportQueue::new();

        let hdr1 = BlockHeader::with_id(1, Some(1337u64));
        let hdr1_1 = BlockHeader::with_id(11, Some(hdr1.id));
        let hdr1_1_1 = BlockHeader::with_id(111, Some(hdr1_1.id));
        let hdr2 = BlockHeader::with_id(2, Some(1337u64));
        let hdr1_2 = BlockHeader::with_id(12, Some(hdr1.id));

        // queue the blocks in in correct order that even if
        // they create temporary export structures, in the end
        // they are merged together and only one `QueuedData` is returned
        assert_eq!(q.try_queue(&hdr1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr1_1_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr1_2), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr2), Ok(ImportQueueState::Queued));

        assert_eq!(
            q.export,
            HashMap::from([
                (11, OrderedData(vec![vec![hdr1_1_1]])),
                (1337, OrderedData(vec![vec![hdr1, hdr2], vec![hdr1_2]]))
            ])
        );

        let block = &BlockHeader::with_id(1337, Some(1336));
        assert_eq!(q.try_queue(block), Ok(ImportQueueState::Resolved));
        assert_eq!(
            q.drain_with_id(&block.id),
            Some(QueuedData(vec![hdr1, hdr2, hdr1_2])),
        );

        assert_eq!(
            q.export,
            HashMap::from([(11, OrderedData(vec![vec![hdr1_1_1]])),])
        );
        assert_eq!(q.try_queue(&hdr1_1), Ok(ImportQueueState::Resolved));
        assert_eq!(
            q.drain_with_id(&hdr1_1.id),
            Some(QueuedData(vec![hdr1_1_1]))
        );
    }

    #[test]
    fn out_of_order_temporarily_resolved() {
        let mut q = ImportQueue::new();

        let hdr1 = BlockHeader::with_id(1, Some(1337u64));
        let hdr2 = BlockHeader::with_id(2, Some(1337u64));
        let hdr1_1 = BlockHeader::with_id(11, Some(hdr1.id));
        let hdr2_1 = BlockHeader::with_id(21, Some(hdr2.id));
        let hdr1_1_1 = BlockHeader::with_id(111, Some(hdr1_1.id));

        // blocks may come in any order
        assert_eq!(q.try_queue(&hdr1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr1_1_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr2_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr1_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.try_queue(&hdr2), Ok(ImportQueueState::Queued));

        assert_eq!(q.num_chains(), 1);
        assert_eq!(q.num_queued(), 5);

        let missing = BlockHeader::with_id(1337u64, Some(1336u64));
        assert_eq!(q.try_queue(&missing), Ok(ImportQueueState::Resolved));
        assert_eq!(
            q.drain_with_id(&missing.id),
            Some(QueuedData(vec![hdr1, hdr2, hdr1_1, hdr2_1, hdr1_1_1]))
        );
        assert_eq!(q.num_chains(), 0);
        assert_eq!(q.num_queued(), 0);
    }

    #[test]
    fn test_queue() {
        let mut q = ImportQueue::new();

        let hdr1 = BlockHeader::with_id(100, Some(1));
        let hdr1_1 = BlockHeader::with_id(101, Some(100));
        let hdr1_1_1 = BlockHeader::with_id(103, Some(102));
        let hdr2 = BlockHeader::with_id(201, Some(100));
        let hdr1_2 = BlockHeader::with_id(202, Some(201));

        assert_eq!(q.queue(hdr1_1_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(hdr1_2), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(hdr2), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(hdr1_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(hdr1), Ok(ImportQueueState::Queued));
        assert_eq!(q.num_chains(), 2);

        assert_eq!(
            q.drain().iter().flat_map(|x| x.to_vec()).sorted().collect::<Vec<BlockHeader>>(),
            [
                BlockHeader::with_id(100, Some(1)),
                BlockHeader::with_id(101, Some(100)),
                BlockHeader::with_id(103, Some(102)),
                BlockHeader::with_id(201, Some(100)),
                BlockHeader::with_id(202, Some(201)),
            ]
        )
    }

    // in total there are 100 new blocks, drain the queue periodically and verify that
    // whatever the order which the blocks came in might have been, they are exported
    // in order (== no orphans when imported to local block index)
    #[test]
    fn test_periodic_draining() {
        let mut q = ImportQueue::new();
        let mut blocks = (2..102).map(|i| BlockHeader::with_id(i, Some(i - 1))).collect::<Vec<_>>();

        // shuffle the blocks so that they are imported to the queue in completely random order
        let orig = blocks.clone();
        blocks.shuffle(&mut rand::thread_rng());
        assert_ne!(orig, blocks);

        // current best block in local block index
        let mut exported = vec![BlockHeader::with_id(1, Some(0))];

        for block in blocks {
            q.queue(block);
            if let Some(drained) = q.drain_with_id(&exported[exported.len() - 1].id) {
                exported.append(&mut drained.to_vec());
            }
        }

        assert_eq!(exported[1..], orig);
    }

    // TODO: add more tests
}
