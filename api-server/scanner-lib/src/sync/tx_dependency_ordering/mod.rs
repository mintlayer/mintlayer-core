// Copyright (c) 2026 RBB S.r.l
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

use std::collections::{BTreeMap, BinaryHeap};

use common::{
    chain::{ChainConfig, SignedTransaction},
    primitives::BlockHeight,
};

mod dependency_graph;

use dependency_graph::{build_dependency_graph, DependencyNode};

// Order transactions by dependency between each other.
// Returns a Vec of transactions starting from the top-most parent transaction
// which doesn't depend on any other transaction fallowing it, and ending with the leafs.
pub fn order_transactions_by_dependency(
    transactions: Vec<SignedTransaction>,
    chain_config: &ChainConfig,
    block_height: BlockHeight,
) -> Result<Vec<SignedTransaction>, TopoSortError> {
    let graph = build_dependency_graph(transactions, chain_config, block_height);

    let sorted_graph = topological_sort(graph)?;

    let sorted_transactions =
        sorted_graph.into_iter().map(|node| node.into_signed_transaction()).collect();

    Ok(sorted_transactions)
}

/// Errors that can occur during topological sorting.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum TopoSortError {
    #[error("Circular dependency was detected")]
    CycleDetected,
    #[error("A node declared a dependency that is not present in the provided vector.")]
    MissingDependency,
}

/// Sorts a vector of `DependencyNode`s topologically.
///
/// Items with no dependencies (roots) will appear first in the resulting vector.
fn topological_sort<T>(nodes: Vec<T>) -> Result<Vec<T>, TopoSortError>
where
    T: DependencyNode,
{
    struct QueueItem<P: Ord> {
        idx: usize,
        priority: P,
    }

    impl<P: Ord> PartialEq for QueueItem<P> {
        fn eq(&self, other: &Self) -> bool {
            self.idx == other.idx
        }
    }

    impl<P: Ord> Eq for QueueItem<P> {}

    impl<P: Ord> Ord for QueueItem<P> {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.priority.cmp(&other.priority)
        }
    }

    impl<P: Ord> PartialOrd for QueueItem<P> {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    let n = nodes.len();
    if n <= 1 {
        return Ok(nodes);
    }

    // Map each node's ID to its index in the original vector.
    let mut id_to_index = BTreeMap::new();
    for (i, node) in nodes.iter().enumerate() {
        id_to_index.insert(node.id(), i);
    }

    // Adjacency list: dependents[i] contains indices of nodes that depend on node i.
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];
    // Indegree: indegrees[i] is the number of unresolved dependencies node i has.
    let mut indegrees: Vec<usize> = vec![0; n];

    // Build the graph
    for (i, node) in nodes.iter().enumerate() {
        for dep_id in node.dependencies() {
            let dep_index = id_to_index.get(dep_id).ok_or(TopoSortError::MissingDependency)?;

            dependents[*dep_index].push(i);
            indegrees[i] += 1;
        }
    }

    // Start with all nodes that have 0 dependencies (the "roots")
    let mut queue = BinaryHeap::new();
    for (idx, node) in nodes.iter().enumerate() {
        if indegrees[idx] == 0 {
            queue.push(QueueItem {
                idx,
                priority: node.priority(),
            });
        }
    }

    let mut sorted_indices = Vec::with_capacity(n);

    while let Some(QueueItem {
        idx: current_idx, ..
    }) = queue.pop()
    {
        sorted_indices.push(current_idx);

        // For every node that depends on the current node, remove the dependency edge
        for &dependent_idx in &dependents[current_idx] {
            indegrees[dependent_idx] -= 1;

            // If the dependent node now has no pending dependencies, it's ready to be processed
            if indegrees[dependent_idx] == 0 {
                queue.push(QueueItem {
                    idx: dependent_idx,
                    priority: nodes[dependent_idx].priority(),
                });
            }
        }
    }

    // If we haven't sorted all items, there must be a cycle
    if sorted_indices.len() != n {
        return Err(TopoSortError::CycleDetected);
    }

    // Reconstruct the sorted vector without cloning `T`
    // We wrap the original items in Option, and `take()` them out in sorted order.
    let mut wrapped_nodes: Vec<Option<T>> = nodes.into_iter().map(Some).collect();

    let sorted_nodes = sorted_indices
        .into_iter()
        .map(|idx| wrapped_nodes[idx].take().expect("present"))
        .collect();

    Ok(sorted_nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use randomness::SliceRandom;
    use test_utils::random::Seed;

    use crate::sync::tx_dependency_ordering::dependency_graph::TxPriorityOrder;

    use rstest::rstest;

    #[derive(Debug, PartialEq, Eq, Clone)]
    struct DummyNode {
        priority: TxPriorityOrder,
        id: u32,
        dependencies: Vec<u32>,
    }

    impl DependencyNode for DummyNode {
        type Id = u32;
        type Priority = TxPriorityOrder;

        fn id(&self) -> Self::Id {
            self.id
        }

        fn priority(&self) -> Self::Priority {
            self.priority
        }

        fn dependencies(&self) -> &[Self::Id] {
            &self.dependencies
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_priority_ordering(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let root_node = DummyNode {
            priority: TxPriorityOrder::Highest,
            id: 1,
            dependencies: vec![],
        };
        let root_freeze_node = DummyNode {
            priority: TxPriorityOrder::TokenFreeze,
            id: 4,
            dependencies: vec![],
        };
        let highest_dependent_node = DummyNode {
            priority: TxPriorityOrder::Highest,
            id: 5,
            dependencies: vec![1],
        };
        let delegation_stake_node = DummyNode {
            priority: TxPriorityOrder::DelegationStake,
            id: 2,
            dependencies: vec![1],
        };
        let delegation_withdrawal_node = DummyNode {
            priority: TxPriorityOrder::DelegationWithdrawal,
            id: 3,
            dependencies: vec![1],
        };
        let expected_sorted_ids = vec![
            // should be first as everyone depends on it
            root_node.id,
            // those depend on the root but internaly will be ordered highest, stake then withdrawal
            highest_dependent_node.id,
            delegation_stake_node.id,
            delegation_withdrawal_node.id,
            // even though this has no dependencies it should still be last by priority
            root_freeze_node.id,
        ];
        let mut nodes = vec![
            root_freeze_node,
            delegation_withdrawal_node,
            delegation_stake_node,
            highest_dependent_node,
            root_node,
        ];
        nodes.shuffle(&mut rng);
        let sorted_nodes = topological_sort(nodes).unwrap();
        let sorted_ids = sorted_nodes.iter().map(|node| node.id).collect::<Vec<_>>();

        assert_eq!(sorted_ids, expected_sorted_ids);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_dependency_ordering(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let root_node = DummyNode {
            priority: TxPriorityOrder::Highest,
            id: 1,
            dependencies: vec![],
        };
        let dependent_node = DummyNode {
            priority: TxPriorityOrder::TokenFreeze,
            id: 2,
            dependencies: vec![1],
        };
        // even though this has higher priorty than TokenFreeze it still depends on it
        let dependent_node2 = DummyNode {
            priority: TxPriorityOrder::Highest,
            id: 3,
            dependencies: vec![2],
        };
        let mut nodes = vec![dependent_node, root_node, dependent_node2];
        nodes.shuffle(&mut rng);
        let sorted_nodes = topological_sort(nodes).unwrap();
        let sorted_ids = sorted_nodes.iter().map(|node| node.id).collect::<Vec<_>>();

        assert_eq!(sorted_ids, vec![1, 2, 3]);
    }

    #[test]
    fn test_diamond_dependency_pattern() {
        // Graph: A -> B, A -> C, B -> D, C -> D
        let a = DummyNode {
            priority: TxPriorityOrder::Highest,
            id: 1,
            dependencies: vec![],
        };
        let b = DummyNode {
            priority: TxPriorityOrder::Highest,
            id: 2,
            dependencies: vec![1],
        };
        let c = DummyNode {
            priority: TxPriorityOrder::Highest,
            id: 3,
            dependencies: vec![1],
        };
        let d = DummyNode {
            priority: TxPriorityOrder::Highest,
            id: 4,
            dependencies: vec![2, 3],
        };

        let sorted = topological_sort(vec![d, b, a, c]).unwrap();
        let sorted_ids = sorted.iter().map(|n| n.id).collect::<Vec<_>>();

        assert_eq!(sorted_ids.first(), Some(&1)); // A must be first
        assert_eq!(sorted_ids.last(), Some(&4)); // D must be last
    }

    #[test]
    fn test_disconnected_components() {
        // Graph: A -> B (Chain 1) and C -> D (Chain 2)
        let a = DummyNode {
            priority: TxPriorityOrder::Highest,
            id: 1,
            dependencies: vec![],
        };
        let b = DummyNode {
            priority: TxPriorityOrder::Highest,
            id: 2,
            dependencies: vec![1],
        };
        let c = DummyNode {
            priority: TxPriorityOrder::Highest,
            id: 3,
            dependencies: vec![],
        };
        let d = DummyNode {
            priority: TxPriorityOrder::Highest,
            id: 4,
            dependencies: vec![3],
        };

        let sorted = topological_sort(vec![d, b, a, c]).unwrap();
        let sorted_ids = sorted.iter().map(|n| n.id).collect::<Vec<_>>();

        // Dependencies must be respected
        let pos_a = sorted_ids.iter().position(|&id| id == 1).unwrap();
        let pos_b = sorted_ids.iter().position(|&id| id == 2).unwrap();
        let pos_c = sorted_ids.iter().position(|&id| id == 3).unwrap();
        let pos_d = sorted_ids.iter().position(|&id| id == 4).unwrap();

        assert!(pos_a < pos_b);
        assert!(pos_c < pos_d);
    }

    #[test]
    fn test_cycle_detection() {
        let root_node = DummyNode {
            priority: TxPriorityOrder::Highest,
            id: 1,
            dependencies: vec![2],
        };
        let dependent_node = DummyNode {
            priority: TxPriorityOrder::Highest,
            id: 2,
            dependencies: vec![1],
        };
        let nodes = vec![root_node, dependent_node];
        let err = topological_sort(nodes).unwrap_err();

        assert_eq!(err, TopoSortError::CycleDetected);
    }

    #[test]
    fn test_missing_dependency() {
        let node1 = DummyNode {
            priority: TxPriorityOrder::Highest,
            id: 1,
            dependencies: vec![2],
        };
        let node2 = DummyNode {
            priority: TxPriorityOrder::Highest,
            id: 2,
            // 3 is not in the nodes list
            dependencies: vec![3],
        };
        let nodes = vec![node1, node2];
        let err = topological_sort(nodes).unwrap_err();

        assert_eq!(err, TopoSortError::MissingDependency);
    }

    #[test]
    fn test_empty_input() {
        let nodes: Vec<DummyNode> = vec![];
        let sorted_nodes = topological_sort(nodes).unwrap();

        assert!(sorted_nodes.is_empty());
    }

    #[test]
    fn test_single_node() {
        let root_node = DummyNode {
            priority: TxPriorityOrder::Highest,
            id: 1,
            dependencies: vec![],
        };
        let nodes = vec![root_node];
        let sorted_nodes = topological_sort(nodes).unwrap();
        let sorted_ids = sorted_nodes.iter().map(|node| node.id).collect::<Vec<_>>();

        assert_eq!(sorted_ids, vec![1]);
    }
}
