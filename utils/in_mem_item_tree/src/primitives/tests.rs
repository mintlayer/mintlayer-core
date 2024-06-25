// Copyright (c) 2021-2024 RBB S.r.l
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

use std::collections::BTreeMap;

use itertools::Itertools;

use ::test_utils::assert_matches;

use super::{
    arena::Arena, detail::ItemIdMapHolder, node_id::NodeId, DataItem, Error, Flavor,
    WithDebugOnlyChecks, WithItemIdToNodeIdMap,
};

type TestItemId = u64;

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
struct TestItem {
    id: TestItemId,
    parent_id: TestItemId,
}

#[derive(Debug, Clone, Copy)]
struct TestIdClassifier {
    genesis_id: TestItemId,
}

impl DataItem for TestItem {
    type Id = TestItemId;
    type IdClassifier = TestIdClassifier;

    fn item_id(&self) -> &Self::Id {
        &self.id
    }

    fn parent_item_id(&self, id_classifier: &TestIdClassifier) -> Option<&Self::Id> {
        (self.parent_id != id_classifier.genesis_id).then_some(&self.parent_id)
    }
}

fn test_item(id: TestItemId, parent_id: TestItemId) -> TestItem {
    TestItem { id, parent_id }
}

fn test_impl<F: Flavor>(
    observer_map_getter: impl Fn(&Arena<TestItem, F>) -> &BTreeMap<TestItemId, NodeId>,
    node_id_by_item_id_getter: impl Fn(&Arena<TestItem, F>, TestItemId) -> Option<NodeId>,
) {
    let genesis_id = 12345;
    let id_classifier = TestIdClassifier { genesis_id };

    let mut arena = Arena::<TestItem, F>::new(id_classifier);
    assert_eq!(arena.capacity(), 0);
    arena.reserve(1000);
    assert!(arena.capacity() >= 1000);
    let mut arena = Arena::<TestItem, F>::with_capacity(1000, id_classifier);
    assert!(arena.capacity() >= 1000);
    assert_eq!(arena.count(), 0);
    assert!(arena.is_empty());

    let node1 = arena.new_node(test_item(1, genesis_id)).unwrap();
    assert!(!node1.is_removed(&arena));
    assert!(!arena.is_empty());
    assert_eq!(arena.count(), 1);
    assert_eq!(observer_map_getter(&arena), &BTreeMap::from([(1, node1)]));
    let mut node1_mut = arena.get_mut(node1).unwrap();
    assert_eq!(node1_mut.get_mut(), &test_item(1, genesis_id));
    assert_eq!(node1_mut.parent(), None);
    assert_eq!(node1_mut.first_child(), None);
    assert_eq!(node1_mut.last_child(), None);
    assert_eq!(node1_mut.previous_sibling(), None);
    assert_eq!(node1_mut.next_sibling(), None);
    // Check that the "gen" functions all return the same pointer.
    let node1_ptr1 = node1_mut.0 as *const _;
    let node1_ptr2 = arena.get_existing_mut(node1).unwrap().0 as *const _;
    let node1_ptr3 = arena.get(node1).unwrap().0 as *const _;
    let node1_ptr4 = arena.get_existing(node1).unwrap().0 as *const _;
    assert!(node1_ptr1 == node1_ptr2);
    assert!(node1_ptr1 == node1_ptr3);
    assert!(node1_ptr1 == node1_ptr4);
    // Check get_node_id.
    assert_eq!(arena.get_node_id(arena.get(node1).unwrap()).unwrap(), node1);

    // Adding a new node corresponding to an existing item id should fail.
    assert_matches!(
        arena.new_node(test_item(1, genesis_id)),
        Err(Error::ItemAlreadyInArena { .. })
    );
    assert_eq!(observer_map_getter(&arena), &BTreeMap::from([(1, node1)]));

    // Add more nodes, using item 1 as the parent.
    let node11 = arena.new_node(test_item(11, 1)).unwrap();
    assert!(!node11.is_removed(&arena));
    assert!(!arena.is_empty());
    assert_eq!(arena.count(), 2);
    assert_eq!(
        observer_map_getter(&arena),
        &BTreeMap::from([(1, node1), (11, node11)])
    );
    let node12 = arena.new_node(test_item(12, 1)).unwrap();
    assert!(!node12.is_removed(&arena));
    assert!(!arena.is_empty());
    assert_eq!(arena.count(), 3);
    assert_eq!(
        observer_map_getter(&arena),
        &BTreeMap::from([(1, node1), (11, node11), (12, node12)])
    );
    let node13 = arena.new_node(test_item(13, 1)).unwrap();
    assert!(!node13.is_removed(&arena));
    assert!(!arena.is_empty());
    assert_eq!(arena.count(), 4);
    assert_eq!(
        observer_map_getter(&arena),
        &BTreeMap::from([(1, node1), (11, node11), (12, node12), (13, node13)])
    );
    // Add a node, using an unknown item 9 as the parent.
    let node91 = arena.new_node(test_item(91, 9)).unwrap();
    assert!(!node91.is_removed(&arena));
    assert!(!arena.is_empty());
    assert_eq!(arena.count(), 5);
    assert_eq!(
        observer_map_getter(&arena),
        &BTreeMap::from([(1, node1), (11, node11), (12, node12), (13, node13), (91, node91)])
    );

    // Set node1x as children of node1 using both append_child and prepend_child.
    node1.append_child(node12, &mut arena).unwrap();
    node1.prepend_child(node11, &mut arena).unwrap();
    node1.append_child(node13, &mut arena).unwrap();
    // Doing the same for node91 should fail.
    assert_matches!(
        node1.append_child(node91, &mut arena),
        Err(Error::NotParentChild { .. })
    );
    assert_matches!(
        node1.prepend_child(node91, &mut arena),
        Err(Error::NotParentChild { .. })
    );
    // Check `children` and `reverse_children`
    assert_eq!(
        node1.children(&arena).collect_vec(),
        &[node11, node12, node13]
    );
    assert_eq!(
        node1.reverse_children(&arena).collect_vec(),
        &[node13, node12, node11]
    );
    // Check node1 accessors again, now first_child and last_child shouldn't be None.
    let node1_ref = arena.get(node1).unwrap();
    assert_eq!(node1_ref.get(), &test_item(1, genesis_id));
    assert_eq!(node1_ref.parent(), None);
    assert_eq!(node1_ref.first_child(), Some(node11));
    assert_eq!(node1_ref.last_child(), Some(node13));
    assert_eq!(node1_ref.previous_sibling(), None);
    assert_eq!(node1_ref.next_sibling(), None);
    // Do the same for node12; previous_sibling/next_sibling shouldn't be None.
    let node12_ref = arena.get(node12).unwrap();
    assert_eq!(node12_ref.get(), &test_item(12, 1));
    assert_eq!(node12_ref.parent(), Some(node1));
    assert_eq!(node12_ref.first_child(), None);
    assert_eq!(node12_ref.last_child(), None);
    assert_eq!(node12_ref.previous_sibling(), Some(node11));
    assert_eq!(node12_ref.next_sibling(), Some(node13));

    // Check get_node_id for node1 again, and also for node12.
    assert_eq!(arena.get_node_id(arena.get(node1).unwrap()).unwrap(), node1);
    assert_eq!(
        arena.get_node_id(arena.get(node12).unwrap()).unwrap(),
        node12
    );

    // Detach node12 from its parent, check accessors again.
    node12.detach_from_parent(&mut arena).unwrap();
    let node1_ref = arena.get(node1).unwrap();
    assert_eq!(node1_ref.get(), &test_item(1, genesis_id));
    assert_eq!(node1_ref.parent(), None);
    assert_eq!(node1_ref.first_child(), Some(node11));
    assert_eq!(node1_ref.last_child(), Some(node13));
    assert_eq!(node1_ref.previous_sibling(), None);
    assert_eq!(node1_ref.next_sibling(), None);
    // node12 has no parent and no siblings
    let node12_ref = arena.get(node12).unwrap();
    assert_eq!(node12_ref.get(), &test_item(12, 1));
    assert_eq!(node12_ref.parent(), None);
    assert_eq!(node12_ref.first_child(), None);
    assert_eq!(node12_ref.last_child(), None);
    assert_eq!(node12_ref.previous_sibling(), None);
    assert_eq!(node12_ref.next_sibling(), None);

    // The observer's map hasn't been affected.
    assert_eq!(
        observer_map_getter(&arena),
        &BTreeMap::from([(1, node1), (11, node11), (12, node12), (13, node13), (91, node91)])
    );

    // Append node12 again.
    node1.append_child(node12, &mut arena).unwrap();
    let node1_ref = arena.get(node1).unwrap();
    assert_eq!(node1_ref.get(), &test_item(1, genesis_id));
    assert_eq!(node1_ref.parent(), None);
    assert_eq!(node1_ref.first_child(), Some(node11));
    // Note: node12 is now the last child.
    assert_eq!(node1_ref.last_child(), Some(node12));
    assert_eq!(node1_ref.previous_sibling(), None);
    assert_eq!(node1_ref.next_sibling(), None);
    // Do the same for node12; previous_sibling/next_sibling shouldn't be None.
    let node12_ref = arena.get(node12).unwrap();
    assert_eq!(node12_ref.get(), &test_item(12, 1));
    assert_eq!(node12_ref.parent(), Some(node1));
    assert_eq!(node12_ref.first_child(), None);
    assert_eq!(node12_ref.last_child(), None);
    assert_eq!(node12_ref.previous_sibling(), Some(node13));
    assert_eq!(node12_ref.next_sibling(), None);

    // Add a child to node12.
    let node121 = arena.new_node(test_item(121, 12)).unwrap();
    assert!(!node121.is_removed(&arena));
    assert!(!arena.is_empty());
    assert_eq!(arena.count(), 6);
    assert_eq!(
        observer_map_getter(&arena),
        &BTreeMap::from([
            (1, node1),
            (11, node11),
            (12, node12),
            (13, node13),
            (91, node91),
            (121, node121),
        ])
    );
    node12.append_child(node121, &mut arena).unwrap();

    // Check ancestors/predecessors on node121.
    assert_eq!(
        node121.ancestors(&arena).collect_vec(),
        &[node121, node12, node1]
    );
    assert_eq!(
        node121.predecessors(&arena).collect_vec(),
        &[node121, node12, node13, node11, node1]
    );
    // Check preceding_siblings/following_siblings on node12 and node13.
    assert_eq!(
        node12.preceding_siblings(&arena).collect_vec(),
        &[node12, node13, node11]
    );
    assert_eq!(
        node13.preceding_siblings(&arena).collect_vec(),
        &[node13, node11]
    );
    assert_eq!(node12.following_siblings(&arena).collect_vec(), &[node12]);
    assert_eq!(
        node13.following_siblings(&arena).collect_vec(),
        &[node13, node12]
    );
    // Check descendants on node1.
    assert_eq!(
        node1.descendants(&arena).collect_vec(),
        &[node1, node11, node13, node12, node121]
    );

    // Create a node and remove it immediately
    let node122 = arena.new_node(test_item(122, 12)).unwrap();
    assert!(!node122.is_removed(&arena));
    assert!(!arena.is_empty());
    assert_eq!(arena.count(), 7);
    assert_eq!(
        observer_map_getter(&arena),
        &BTreeMap::from([
            (1, node1),
            (11, node11),
            (12, node12),
            (13, node13),
            (91, node91),
            (121, node121),
            (122, node122),
        ])
    );
    // The "get" functions have already been tested above, so only check that they return Some/Ok here.
    assert!(arena.get(node122).is_some());
    assert!(arena.get_existing(node122).is_ok());
    assert!(arena.get_mut(node122).is_some());
    assert!(arena.get_existing_mut(node122).is_ok());
    // Now remove the node.
    node122.remove_subtree(&mut arena).unwrap();
    assert!(node122.is_removed(&arena));
    assert!(!arena.is_empty());
    // The arena nodes count stays the same.
    assert_eq!(arena.count(), 7);
    // The "get" functions should now fail.
    assert!(arena.get(node122).is_none());
    assert_matches!(arena.get_existing(node122), Err(Error::NodeIsRemoved(_)));
    assert!(arena.get_mut(node122).is_none());
    assert_matches!(
        arena.get_existing_mut(node122),
        Err(Error::NodeIsRemoved(_))
    );
    assert_eq!(
        observer_map_getter(&arena),
        &BTreeMap::from([
            (1, node1),
            (11, node11),
            (12, node12),
            (13, node13),
            (91, node91),
            (121, node121),
        ])
    );

    // Appending/prepending the removed node fails with an error.
    assert_matches!(
        node12.append_child(node122, &mut arena),
        Err(Error::NodeIsRemoved(_))
    );
    assert_matches!(
        node12.prepend_child(node122, &mut arena),
        Err(Error::NodeIsRemoved(_))
    );

    let non_existent_node_id = {
        let mut other_arena = Arena::<TestItem, F>::new(id_classifier);

        let mut last_node_id = None;
        for i in 0..100 {
            last_node_id = Some(other_arena.new_node(test_item(i, genesis_id)).unwrap());
        }

        last_node_id.unwrap()
    };

    // Appending/prepending a non-existent node id fails with an error.
    assert_matches!(
        node12.append_child(non_existent_node_id, &mut arena),
        Err(Error::NodeIdNotInArena(_))
    );
    assert_matches!(
        node12.prepend_child(non_existent_node_id, &mut arena),
        Err(Error::NodeIdNotInArena(_))
    );

    // Create a new node after the removal. The previously removed node must be reused.
    let node123 = arena.new_node(test_item(123, 12)).unwrap();
    // The node id is different from the removed one.
    assert!(node123 != node122);
    // node122 is still removed, node123 is not
    assert!(node122.is_removed(&arena));
    assert!(!node123.is_removed(&arena));
    assert!(!arena.is_empty());
    // But the number of nodes int he arena hasn't changed.
    assert_eq!(arena.count(), 7);
    assert_eq!(
        observer_map_getter(&arena),
        &BTreeMap::from([
            (1, node1),
            (11, node11),
            (12, node12),
            (13, node13),
            (91, node91),
            (121, node121),
            (123, node123),
        ])
    );
    node12.append_child(node123, &mut arena).unwrap();

    // Try removing a non-existent subtree.
    assert_matches!(
        non_existent_node_id.remove_subtree(&mut arena),
        Err(Error::NodeIdNotInArena(_))
    );

    // Check node_id_by_item_id
    assert_eq!(node_id_by_item_id_getter(&arena, 1), Some(node1));
    assert_eq!(node_id_by_item_id_getter(&arena, 91), Some(node91));
    assert_eq!(node_id_by_item_id_getter(&arena, 11), Some(node11));
    assert_eq!(node_id_by_item_id_getter(&arena, 12), Some(node12));
    assert_eq!(node_id_by_item_id_getter(&arena, 13), Some(node13));
    assert_eq!(node_id_by_item_id_getter(&arena, 121), Some(node121));
    assert_eq!(node_id_by_item_id_getter(&arena, 122), None);
    assert_eq!(node_id_by_item_id_getter(&arena, 123), Some(node123));

    // Remove the whole node1 subtree.
    node1.remove_subtree(&mut arena).unwrap();
    // The number of nodes stays he same.
    assert!(!arena.is_empty());
    assert_eq!(arena.count(), 7);
    assert!(!node91.is_removed(&arena));
    assert!(node1.is_removed(&arena));
    assert!(node11.is_removed(&arena));
    assert!(node12.is_removed(&arena));
    assert!(node13.is_removed(&arena));
    assert!(node121.is_removed(&arena));
    assert!(node122.is_removed(&arena));
    assert!(node123.is_removed(&arena));
    assert_eq!(
        observer_map_getter(&arena),
        &BTreeMap::from([(91, node91),])
    );

    // Check node_id_by_item_id again
    assert_eq!(node_id_by_item_id_getter(&arena, 1), None);
    assert_eq!(node_id_by_item_id_getter(&arena, 91), Some(node91));
    assert_eq!(node_id_by_item_id_getter(&arena, 11), None);
    assert_eq!(node_id_by_item_id_getter(&arena, 12), None);
    assert_eq!(node_id_by_item_id_getter(&arena, 13), None);
    assert_eq!(node_id_by_item_id_getter(&arena, 121), None);
    assert_eq!(node_id_by_item_id_getter(&arena, 122), None);
    assert_eq!(node_id_by_item_id_getter(&arena, 123), None);

    // Clear the entire arena.
    arena.clear();
    // Now it's empty again
    assert!(arena.is_empty());
    assert_eq!(arena.count(), 0);
    assert_eq!(observer_map_getter(&arena), &BTreeMap::new());

    // Check node_id_by_item_id again
    assert_eq!(node_id_by_item_id_getter(&arena, 1), None);
    assert_eq!(node_id_by_item_id_getter(&arena, 91), None);
    assert_eq!(node_id_by_item_id_getter(&arena, 11), None);
    assert_eq!(node_id_by_item_id_getter(&arena, 12), None);
    assert_eq!(node_id_by_item_id_getter(&arena, 13), None);
    assert_eq!(node_id_by_item_id_getter(&arena, 121), None);
    assert_eq!(node_id_by_item_id_getter(&arena, 122), None);
    assert_eq!(node_id_by_item_id_getter(&arena, 123), None);
}

#[test]
fn test() {
    test_impl::<WithItemIdToNodeIdMap>(
        |arena| arena.modification_observer.item_id_map(),
        |arena, item_id| {
            let node_id_by_item_id = arena.node_id_by_item_id(&item_id);
            let node_id_in_map = arena.modification_observer.item_id_map().get(&item_id).copied();
            assert_eq!(node_id_by_item_id, node_id_in_map);
            node_id_by_item_id
        },
    );

    #[cfg(debug_assertions)]
    {
        test_impl::<WithDebugOnlyChecks>(
            |arena| arena.modification_observer.inner().item_id_map(),
            |arena, item_id| {
                arena.modification_observer.inner().item_id_map().get(&item_id).copied()
            },
        );
    }
}
