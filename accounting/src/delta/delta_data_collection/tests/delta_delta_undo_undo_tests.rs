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

type FourCollections = (
    DeltaDataCollection<i32, char>,
    DeltaDataCollection<i32, char>,
    DeltaDataCollection<i32, char>,
    DeltaDataCollection<i32, char>,
);

#[rstest]
#[case(make_create_modify_undo_undo_collections())]
#[case(make_create_delete_undo_undo_collections())]
#[case(make_modify_modify_undo_undo_collections())]
#[case(make_modify_delete_undo_undo_collections())]
fn delta_delta_undo_undo_associativity(#[case] collections: FourCollections) {
    let expected_collection = DeltaDataCollection::new();

    {
        // Delta1 + Delta2 + Undo1 + Undo2 = No-op
        let (mut collection1, collection2, collection3, collection4) = collections.clone();
        let _ = collection1.merge_delta_data(collection2).unwrap();
        let _ = collection1.merge_delta_data(collection3).unwrap();
        let _ = collection1.merge_delta_data(collection4).unwrap();

        assert_eq!(collection1, expected_collection);
    }

    {
        // (Delta1 + Delta2) + (Undo1 + Undo2) = No-op
        let (mut collection1, collection2, mut collection3, collection4) = collections.clone();
        let _ = collection1.merge_delta_data(collection2).unwrap();
        let _ = collection3.merge_delta_data(collection4).unwrap();
        let _ = collection1.merge_delta_data(collection3).unwrap();

        assert_eq!(collection1, expected_collection);
    }

    {
        // Delta1 + (Delta2 + Undo1 + Undo2) = No-op
        let (mut collection1, mut collection2, collection3, collection4) = collections.clone();
        let _ = collection2.merge_delta_data(collection3).unwrap();
        let _ = collection2.merge_delta_data(collection4).unwrap();
        let _ = collection1.merge_delta_data(collection2).unwrap();

        assert_eq!(collection1, expected_collection);
    }

    {
        // Delta1 + (Delta2 + (Undo1 + Undo2)) = No-op
        let (mut collection1, mut collection2, mut collection3, collection4) = collections;
        let _ = collection3.merge_delta_data(collection4).unwrap();
        let _ = collection2.merge_delta_data(collection3).unwrap();
        let _ = collection1.merge_delta_data(collection2).unwrap();

        assert_eq!(collection1, expected_collection);
    }
}

fn make_create_delete_undo_undo_collections() -> FourCollections {
    let mut collection1 = DeltaDataCollection::new();
    let undo_create = collection1
        .merge_delta_data_element(1, DataDelta::Create(Box::new('a')))
        .unwrap()
        .unwrap();

    let mut collection2 = DeltaDataCollection::new();
    let undo_delete = collection2
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('a')))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_delete).unwrap();

    let mut collection4 = DeltaDataCollection::new();
    collection4.undo_merge_delta_data_element(1, undo_create).unwrap();

    (collection1, collection2, collection3, collection4)
}

fn make_create_modify_undo_undo_collections() -> FourCollections {
    let mut collection1 = DeltaDataCollection::new();
    let undo_create = collection1
        .merge_delta_data_element(1, DataDelta::Create(Box::new('a')))
        .unwrap()
        .unwrap();

    let mut collection2 = DeltaDataCollection::new();
    let undo_modify = collection2
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_modify).unwrap();

    let mut collection4 = DeltaDataCollection::new();
    collection4.undo_merge_delta_data_element(1, undo_create).unwrap();

    (collection1, collection2, collection3, collection4)
}

fn make_modify_modify_undo_undo_collections() -> FourCollections {
    let mut collection1 = DeltaDataCollection::new();
    let undo_modify1 = collection1
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    let mut collection2 = DeltaDataCollection::new();
    let undo_modify2 = collection2
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('b'), Box::new('c'))))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_modify2).unwrap();

    let mut collection4 = DeltaDataCollection::new();
    collection4.undo_merge_delta_data_element(1, undo_modify1).unwrap();

    (collection1, collection2, collection3, collection4)
}

fn make_modify_delete_undo_undo_collections() -> FourCollections {
    let mut collection1 = DeltaDataCollection::new();
    let undo_modify = collection1
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    let mut collection2 = DeltaDataCollection::new();
    let undo_delete = collection2
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('b')))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_delete).unwrap();

    let mut collection4 = DeltaDataCollection::new();
    collection4.undo_merge_delta_data_element(1, undo_modify).unwrap();

    (collection1, collection2, collection3, collection4)
}
