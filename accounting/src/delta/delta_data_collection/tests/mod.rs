// Copyright (c) 2021-2022 RBB S.r.l
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

use super::*;

mod delta_delta_delta_tests;
mod delta_delta_undo_tests;
mod delta_delta_undo_undo_tests;

fn are_delta_and_undo_equivalent<T: Clone + PartialEq>(
    delta: DataDelta<T>,
    undo: DataDeltaUndo<T>,
) -> bool {
    match (delta, undo) {
        (DataDelta::Create(d), DataDeltaUndo::Create(u)) => d == u,
        (DataDelta::Modify(d), DataDeltaUndo::Modify(u)) => d == u,
        (DataDelta::Delete(d), DataDeltaUndo::Delete(u)) => d == u,
        _ => false,
    }
}

#[test]
fn create_delta_undo_roundtrip() {
    let check_undo = |delta1, delta2: DataDelta<char>| {
        let undo = create_undo_delta(delta2.clone());
        let combine_result = combine_deltas(&delta1, delta2).unwrap().unwrap();
        let undo_result = combine_delta_with_undo(&combine_result, undo).unwrap().unwrap();

        match undo_result {
            DeltaMapElement::Delta(result) => assert_eq!(delta1, result),
            DeltaMapElement::DeltaUndo(_) => panic!("shouldn't be undo"),
        };
    };

    check_undo(
        DataDelta::Create(Box::new('a')),
        DataDelta::Modify((Box::new('a'), Box::new('b'))),
    );

    check_undo(
        DataDelta::Modify((Box::new('a'), Box::new('b'))),
        DataDelta::Delete(Box::new('b')),
    );

    check_undo(
        DataDelta::Modify((Box::new('a'), Box::new('b'))),
        DataDelta::Modify((Box::new('b'), Box::new('c'))),
    );
}

// Same as `create_delta_undo_roundtrip` but for deltas that produce No-op
#[test]
fn create_delta_undo_noop_roundtrip() {
    let check_undo = |delta1, delta2: DataDelta<char>| {
        let undo = create_undo_delta(delta2.clone());
        let combine_result = combine_deltas(&delta1, delta2).unwrap();
        assert!(combine_result.is_none());
        assert!(are_delta_and_undo_equivalent(delta1, undo));
    };

    check_undo(
        DataDelta::Modify((Box::new('a'), Box::new('b'))),
        DataDelta::Modify((Box::new('b'), Box::new('a'))),
    );

    check_undo(
        DataDelta::Create(Box::new('a')),
        DataDelta::Delete(Box::new('a')),
    );
}

// FIXME: enable this test
#[test]
#[ignore]
fn merge_collections_and_undo() {
    // This test check all valid combinations:
    //    collection1 - collection2
    //    -------------------------
    //         Create - Modify
    //         Create - Delete
    //         Modify - Modify
    //         Modify - Delete
    //         Delete - Create
    //         Create - None
    //         Modify - None
    //         Delete - None
    //         None   - Create
    //         None   - Modify
    //         None   - Delete

    let mut collection1 = DeltaDataCollection::from_iter(
        [
            (1, DataDelta::Create(Box::new('a'))),
            (2, DataDelta::Create(Box::new('b'))),
            (3, DataDelta::Modify((Box::new('a'), Box::new('c')))),
            (4, DataDelta::Modify((Box::new('a'), Box::new('d')))),
            (5, DataDelta::Delete(Box::new('e'))),
            (6, DataDelta::Create(Box::new('f'))),
            (7, DataDelta::Modify((Box::new('a'), Box::new('g')))),
            (8, DataDelta::Delete(Box::new('h'))),
        ]
        .into_iter(),
    );

    let collection2 = DeltaDataCollection::from_iter(
        [
            (1, DataDelta::Modify((Box::new('a'), Box::new('i')))),
            (2, DataDelta::Delete(Box::new('b'))),
            (3, DataDelta::Modify((Box::new('c'), Box::new('j')))),
            (4, DataDelta::Delete(Box::new('d'))),
            (5, DataDelta::Create(Box::new('e'))),
            (9, DataDelta::Create(Box::new('m'))),
            (10, DataDelta::Modify((Box::new('a'), Box::new('n')))),
            (11, DataDelta::Delete(Box::new('o'))),
        ]
        .into_iter(),
    );

    let expected_data_after_merge = BTreeMap::from_iter(
        [
            (1, DeltaMapElement::Delta(DataDelta::Create(Box::new('i')))),
            (2, DeltaMapElement::Delta(DataDelta::Delete(Box::new('b')))),
            (
                3,
                DeltaMapElement::Delta(DataDelta::Modify((Box::new('a'), Box::new('j')))),
            ),
            (4, DeltaMapElement::Delta(DataDelta::Delete(Box::new('d')))),
            (5, DeltaMapElement::Delta(DataDelta::Create(Box::new('e')))),
            (6, DeltaMapElement::Delta(DataDelta::Create(Box::new('f')))),
            (
                7,
                DeltaMapElement::Delta(DataDelta::Modify((Box::new('a'), Box::new('g')))),
            ),
            (8, DeltaMapElement::Delta(DataDelta::Delete(Box::new('h')))),
            (9, DeltaMapElement::Delta(DataDelta::Create(Box::new('m')))),
            (
                10,
                DeltaMapElement::Delta(DataDelta::Modify((Box::new('a'), Box::new('n')))),
            ),
            (11, DeltaMapElement::Delta(DataDelta::Delete(Box::new('o')))),
        ]
        .into_iter(),
    );

    let undo_data = collection1.merge_delta_data(collection2).unwrap();
    assert_eq!(collection1.data, expected_data_after_merge);

    let expected_data_after_undo = BTreeMap::from_iter(
        [
            (
                1,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('a'))),
            ),
            (
                2,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('b'))),
            ),
            (
                3,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Modify((Box::new('a'), Box::new('c')))),
            ),
            (
                4,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('d'))),
            ),
            (
                5,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Delete(Box::new('e'))),
            ),
            (6, DeltaMapElement::Delta(DataDelta::Create(Box::new('f')))),
            (
                7,
                DeltaMapElement::Delta(DataDelta::Modify((Box::new('a'), Box::new('g')))),
            ),
            (8, DeltaMapElement::Delta(DataDelta::Delete(Box::new('h')))),
            (
                9,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Delete(Box::new('m'))),
            ),
            (
                10,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Modify((Box::new('a'), Box::new('a')))),
            ),
            (
                11,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('o'))),
            ),
        ]
        .into_iter(),
    );
    collection1.undo_merge_delta_data(undo_data).unwrap();
    assert_eq!(collection1.data, expected_data_after_undo);
}

#[test]
fn merge_undo_delta_into_empty_collection() {
    {
        let mut collection: DeltaDataCollection<i32, char> = DeltaDataCollection::new();
        collection
            .undo_merge_delta_data_element(0, DataDeltaUndo::Create(Box::new('a')))
            .unwrap();
        let expected_data = BTreeMap::from_iter(
            [(
                0,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('a'))),
            )]
            .into_iter(),
        );
        assert_eq!(collection.data, expected_data);
    }

    {
        let mut collection: DeltaDataCollection<i32, char> = DeltaDataCollection::new();
        collection
            .undo_merge_delta_data_element(
                0,
                DataDeltaUndo::Modify((Box::new('a'), (Box::new('b')))),
            )
            .unwrap();
        let expected_data = BTreeMap::from_iter(
            [(
                0,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Modify((Box::new('a'), Box::new('b')))),
            )]
            .into_iter(),
        );
        assert_eq!(collection.data, expected_data);
    }

    {
        let mut collection: DeltaDataCollection<i32, char> = DeltaDataCollection::new();
        collection
            .undo_merge_delta_data_element(0, DataDeltaUndo::Delete(Box::new('a')))
            .unwrap();
        let expected_data = BTreeMap::from_iter(
            [(
                0,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Delete(Box::new('a'))),
            )]
            .into_iter(),
        );
        assert_eq!(collection.data, expected_data);
    }
}

#[test]
fn create_delete_undo_same_collection() {
    let mut collection =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());

    let undo = collection
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('a')))
        .unwrap()
        .unwrap();

    collection.undo_merge_delta_data_element(1, undo).unwrap();

    let expected_collection = DeltaDataCollection::from_iter(
        [(
            1,
            DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('a'))),
        )]
        .into_iter(),
    );
    assert_eq!(collection, expected_collection);
}

#[test]
fn create_modify_undo_same_collection() {
    let mut collection =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());
    let expected_collection = collection.clone();

    let undo = collection
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    collection.undo_merge_delta_data_element(1, undo).unwrap();

    assert_eq!(collection, expected_collection);
}

#[test]
fn modify_modify_undo_same_collection() {
    let mut collection = DeltaDataCollection::from_iter(
        [(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))].into_iter(),
    );
    let expected_collection = collection.clone();

    let undo = collection
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('b'), Box::new('c'))))
        .unwrap()
        .unwrap();

    collection.undo_merge_delta_data_element(1, undo).unwrap();

    assert_eq!(collection, expected_collection);
}

#[test]
fn modify_delete_undo_same_collection() {
    let mut collection = DeltaDataCollection::from_iter(
        [(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))].into_iter(),
    );
    let expected_collection = collection.clone();

    let undo = collection
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('b')))
        .unwrap()
        .unwrap();

    collection.undo_merge_delta_data_element(1, undo).unwrap();

    assert_eq!(collection, expected_collection);
}

#[test]
fn create_undo_modify_merge_fail() {
    let mut collection1 = DeltaDataCollection::new();
    let undo_create = collection1
        .merge_delta_data_element(1, DataDelta::Create(Box::new('a')))
        .unwrap()
        .unwrap();

    let mut collection2 = DeltaDataCollection::new();
    collection2.undo_merge_delta_data_element(1, undo_create).unwrap();

    let mut collection3 = DeltaDataCollection::new();
    let _ = collection3
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap();

    assert_eq!(
        collection2.merge_delta_data(collection3).unwrap_err(),
        Error::DeltaOverUndoApplied
    );
}

#[test]
fn create_undo_delete_merge_fail() {
    let mut collection1 = DeltaDataCollection::new();
    let undo_create = collection1
        .merge_delta_data_element(1, DataDelta::Create(Box::new('a')))
        .unwrap()
        .unwrap();

    let mut collection2 = DeltaDataCollection::new();
    collection2.undo_merge_delta_data_element(1, undo_create).unwrap();

    let mut collection3 = DeltaDataCollection::new();
    let _ = collection3
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('a')))
        .unwrap();

    assert_eq!(
        collection2.merge_delta_data(collection3).unwrap_err(),
        Error::DeltaOverUndoApplied
    );
}
