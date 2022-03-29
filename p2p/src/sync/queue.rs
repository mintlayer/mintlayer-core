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
use crate::{error::P2pError, sync::mock_consensus};
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
    ops::{Deref, DerefMut},
};

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
    Queued,
    Resolved,
}

#[derive(Debug, Clone)]
pub struct ImportQueue<T: Orderable> {
    lookup: HashMap<T::Id, (T::Id, usize)>,
    export: HashMap<T::Id, OrderedData<T>>,
}

impl<T: Orderable + Copy + Debug> Default for ImportQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Orderable + Copy + Debug> ImportQueue<T> {
    pub fn new() -> Self {
        Self {
            lookup: HashMap::new(),
            export: HashMap::new(),
        }
    }

    // return the total number of queued elements in the import queue
    pub fn num_queued(&self) -> usize {
        self.lookup.len()
    }

    /// Return the number of individual chains that the import queue is tracking
    pub fn num_chains(&self) -> usize {
        self.export.len()
    }

    fn resolve_deps(&mut self, id: &T::Id) -> Result<ImportQueueState, P2pError> {
        if let Some(exported) = self.export.remove(id) {
            let resolved = QueuedData(exported.0.into_iter().flatten().collect());

            // import all data of the now-resolved descedant and remove all old references
            resolved.0.iter().for_each(|descendant| {
                self.lookup.remove(descendant.get_id());
                self.queue(descendant);
            });
        }

        Ok(ImportQueueState::Queued)
    }

    pub fn queue(&mut self, data: &T) -> Result<ImportQueueState, P2pError> {
        let prev_id = data.get_prev_id().ok_or(P2pError::InvalidData)?;

        // dependency has been resolved if the export table contains an entry with this
        // id but the lookup table doesn't meaning there is no out of order blocks
        if self.export.contains_key(data.get_id()) && !self.lookup.contains_key(&prev_id) {
            return Ok(ImportQueueState::Resolved);
        }

        match self.export.get_mut(&prev_id) {
            Some(ancestor) => {
                ancestor.queue(*data, 0);
                self.lookup.insert(*data.get_id(), (prev_id, 0));
            }
            None => match self.lookup.get(&prev_id) {
                Some(info) => {
                    let (ancestor, idx) = (info.0, info.1 + 1);
                    self.lookup.insert(*data.get_id(), (ancestor, idx));

                    let descendants = self
                        .export
                        .get_mut(&ancestor)
                        .ok_or(P2pError::InvalidData)?
                        .queue(*data, idx);
                }
                None => {
                    self.export.insert(prev_id, OrderedData(vec![vec![*data]]));
                    self.lookup.insert(*data.get_id(), (prev_id, 0));
                }
            },
        }

        return self.resolve_deps(data.get_id());
    }

    /// Get queued descendants
    pub fn get_queued(&mut self, data: &T) -> Option<QueuedData<T>> {
        if let Some(exported) = self.export.remove(data.get_id()) {
            let resolved = QueuedData(exported.0.into_iter().flatten().collect());

            // remove all export and lookup references that are no longer needed
            resolved.0.iter().for_each(|descendant| {
                self.lookup.remove(descendant.get_id()).map_or_else(|| (), |_| ())
            });
            self.lookup.remove(data.get_id());

            return Some(resolved);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::mock_consensus::{BlockHeader, BlockId};

    impl Orderable for BlockHeader {
        type Id = BlockId;

        fn get_id(&self) -> &Self::Id {
            &self.id
        }

        fn get_prev_id(&self) -> &Option<Self::Id> {
            &self.prev_id
        }
    }

    #[test]
    fn add_block() {
        let mut q = ImportQueue::new();

        let hdr1 = BlockHeader::new(Some(1337u64));
        let hdr2 = BlockHeader::new(Some(1337u64));

        assert_eq!(q.queue(&hdr1), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr2), Ok(ImportQueueState::Queued));

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

        assert_eq!(q.queue(&hdr2), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr1), Ok(ImportQueueState::Queued));
        assert_eq!(
            q.export,
            HashMap::from([(1337, OrderedData(vec![vec![hdr2, hdr1]]))])
        );

        let hdr1_1 = BlockHeader {
            id: 1338u64,
            prev_id: Some(hdr1.id),
        };
        assert_eq!(q.queue(&hdr1_1), Ok(ImportQueueState::Queued));
        assert_eq!(
            q.export,
            HashMap::from([(1337, OrderedData(vec![vec![hdr2, hdr1], vec![hdr1_1]]))])
        );

        let hdr1_2 = BlockHeader {
            id: 1339u64,
            prev_id: Some(hdr1.id),
        };
        assert_eq!(q.queue(&hdr1_2), Ok(ImportQueueState::Queued));
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
        assert_eq!(q.queue(&hdr1_1_1), Ok(ImportQueueState::Queued));
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

        assert_eq!(q.queue(&hdr1), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr2), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr1_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr1_2), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr1_1_1), Ok(ImportQueueState::Queued));

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

        assert_eq!(q.queue(&hdr5), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr5_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr5_1_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr5_1_1_1), Ok(ImportQueueState::Queued));

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

        assert_eq!(q.queue(&hdr1), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr2), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr1_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr1_2), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr1_1_1), Ok(ImportQueueState::Queued));

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
        assert_eq!(q.queue(&block), Ok(ImportQueueState::Resolved));
        assert_eq!(
            q.get_queued(&block),
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

        assert_eq!(q.queue(&hdr1), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr2), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr1_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr1_2), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr1_1_1), Ok(ImportQueueState::Queued));

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

        assert_eq!(q.queue(&hdr5), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr5_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr5_1_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr5_1_1_1), Ok(ImportQueueState::Queued));

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
        assert_eq!(q.queue(&block), Ok(ImportQueueState::Resolved));
        assert_eq!(
            q.get_queued(&block),
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
        assert_eq!(q.queue(&block), Ok(ImportQueueState::Resolved));
        assert_eq!(
            q.get_queued(&block),
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
        assert_eq!(q.queue(&hdr1), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr1_1_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr1_1), Ok(ImportQueueState::Queued));

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
        assert_eq!(q.queue(&hdr1), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr1_1_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr1_2), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr2), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr1_1), Ok(ImportQueueState::Queued));

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
        assert_eq!(q.queue(&hdr1), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr1_1_1), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr1_2), Ok(ImportQueueState::Queued));
        assert_eq!(q.queue(&hdr2), Ok(ImportQueueState::Queued));

        assert_eq!(
            q.export,
            HashMap::from([
                (11, OrderedData(vec![vec![hdr1_1_1]])),
                (1337, OrderedData(vec![vec![hdr1, hdr2], vec![hdr1_2]]))
            ])
        );

        let block = &BlockHeader::with_id(1337, Some(1336));
        assert_eq!(q.queue(block), Ok(ImportQueueState::Resolved));
        assert_eq!(
            q.get_queued(block),
            Some(QueuedData(vec![hdr1, hdr2, hdr1_2])),
        );

        assert_eq!(
            q.export,
            HashMap::from([(11, OrderedData(vec![vec![hdr1_1_1]])),])
        );
        assert_eq!(q.queue(&hdr1_1), Ok(ImportQueueState::Resolved));
        assert_eq!(q.get_queued(&hdr1_1), Some(QueuedData(vec![hdr1_1_1])));
    }
}
