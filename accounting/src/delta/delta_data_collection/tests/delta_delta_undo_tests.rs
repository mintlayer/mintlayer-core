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

use rstest::rstest;

type ThreeCollections = (
    DeltaDataCollection<i32, char>,
    DeltaDataCollection<i32, char>,
    DeltaDataCollection<i32, char>,
);

#[rstest]
#[case(make_create_modify_undo_collections())]
#[case(make_modify_modify_undo_collections())]
#[case(make_modify_delete_undo_collections())]
#[case(make_delete_create_undo_collections())]
fn delta_delta_undo_associativity(#[case] collections: ThreeCollections) {
    {
        // Delta1 + Delta2 + Undo = Delta1
        let (mut collection1, collection2, collection3) = collections.clone();
        let expected_collection = collection1.clone();

        let _ = collection1.merge_delta_data(collection2).unwrap();
        let _ = collection1.merge_delta_data(collection3).unwrap();

        assert_eq!(collection1, expected_collection);
    }

    {
        // Delta1 + (Delta2 + Undo) = Delta1
        let (mut collection1, mut collection2, collection3) = collections;
        let expected_collection = collection1.clone();

        let _ = collection2.merge_delta_data(collection3).unwrap();
        let _ = collection1.merge_delta_data(collection2).unwrap();

        assert_eq!(collection1, expected_collection);
    }
}

#[test]
fn create_delete_undo_associativity() {
    {
        // Create(a) + Delete(a) + Undo = No-op + Undo(Delete(a)) = Undo(Delete(a))
        let (mut collection1, collection2, collection3) = make_create_delete_undo_collections();

        let _ = collection1.merge_delta_data(collection2).unwrap();
        let _ = collection1.merge_delta_data(collection3).unwrap();

        let expected_collection = DeltaDataCollection::from_iter(
            [(
                1,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('a'))),
            )]
            .into_iter(),
        );
        assert_eq!(collection1, expected_collection);
    }

    {
        // Create(a) + (Delete(a) + Undo) = Create(a)
        let (mut collection1, mut collection2, collection3) = make_create_delete_undo_collections();
        let expected_collection = collection1.clone();

        let _ = collection2.merge_delta_data(collection3).unwrap();
        let _ = collection1.merge_delta_data(collection2).unwrap();

        assert_eq!(collection1, expected_collection);
    }
}

fn make_create_delete_undo_collections() -> ThreeCollections {
    let collection1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());

    let mut collection2 = DeltaDataCollection::new();
    let undo_delete = collection2
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('a')))
        .unwrap()
        .unwrap();

    let collection3 =
        DeltaDataCollection::from_iter([(1, DeltaMapElement::DeltaUndo(undo_delete))].into_iter());

    (collection1, collection2, collection3)
}

fn make_create_modify_undo_collections() -> ThreeCollections {
    let collection1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());

    let mut collection2 = DeltaDataCollection::new();
    let undo_modify = collection2
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    let collection3 =
        DeltaDataCollection::from_iter([(1, DeltaMapElement::DeltaUndo(undo_modify))].into_iter());

    (collection1, collection2, collection3)
}

fn make_modify_modify_undo_collections() -> ThreeCollections {
    let collection1 = DeltaDataCollection::from_iter(
        [(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))].into_iter(),
    );

    let mut collection2 = DeltaDataCollection::new();
    let undo_modify = collection2
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('b'), Box::new('c'))))
        .unwrap()
        .unwrap();

    let collection3 =
        DeltaDataCollection::from_iter([(1, DeltaMapElement::DeltaUndo(undo_modify))].into_iter());

    (collection1, collection2, collection3)
}

fn make_modify_delete_undo_collections() -> ThreeCollections {
    let collection1 = DeltaDataCollection::from_iter(
        [(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))].into_iter(),
    );

    let mut collection2 = DeltaDataCollection::new();
    let undo_delete = collection2
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('b')))
        .unwrap()
        .unwrap();

    let collection3 =
        DeltaDataCollection::from_iter([(1, DeltaMapElement::DeltaUndo(undo_delete))].into_iter());

    (collection1, collection2, collection3)
}

fn make_delete_create_undo_collections() -> ThreeCollections {
    let collection1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Delete(Box::new('a')))].into_iter());

    let mut collection2 = DeltaDataCollection::new();
    let undo_create = collection2
        .merge_delta_data_element(1, DataDelta::Create(Box::new('b')))
        .unwrap()
        .unwrap();

    let collection3 =
        DeltaDataCollection::from_iter([(1, DeltaMapElement::DeltaUndo(undo_create))].into_iter());

    (collection1, collection2, collection3)
}
