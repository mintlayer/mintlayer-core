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

type ThreeCollections = (
    DeltaDataCollection<i32, char>,
    DeltaDataCollection<i32, char>,
    DeltaDataCollection<i32, char>,
);

#[test]
fn create_modify_modify_associativity() {
    let expected_collection =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('c')))]);

    {
        // Create + Modify + Modify = Create
        let (mut collection1, collection2, collection3) = make_create_modify_modify_collections();
        let _ = collection1.merge_delta_data(collection2).unwrap();
        let _ = collection1.merge_delta_data(collection3).unwrap();

        assert_eq!(collection1, expected_collection);
    }

    {
        // Create + (Modify + Modify) = Create
        let (mut collection1, mut collection2, collection3) =
            make_create_modify_modify_collections();
        let _ = collection2.merge_delta_data(collection3).unwrap();
        let _ = collection1.merge_delta_data(collection2).unwrap();

        assert_eq!(collection1, expected_collection);
    }
}

fn make_create_modify_modify_collections() -> ThreeCollections {
    let mut collection1 = DeltaDataCollection::new();
    let _ = collection1
        .merge_delta_data_element(1, DataDelta::Create(Box::new('a')))
        .unwrap()
        .unwrap();

    let mut collection2 = DeltaDataCollection::new();
    let _ = collection2
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    let _ = collection3
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('b'), Box::new('c'))))
        .unwrap()
        .unwrap();

    (collection1, collection2, collection3)
}

#[test]
fn create_modify_delete_associativity() {
    let expected_collection = DeltaDataCollection::new();

    {
        // Create + Modify + Delete = No-op
        let (mut collection1, collection2, collection3) = make_create_modify_delete_collections();
        let _ = collection1.merge_delta_data(collection2).unwrap();
        let _ = collection1.merge_delta_data(collection3).unwrap();

        assert_eq!(collection1, expected_collection);
    }

    {
        // Create + (Modify + Delete) = No-op
        let (mut collection1, mut collection2, collection3) =
            make_create_modify_delete_collections();
        let _ = collection2.merge_delta_data(collection3).unwrap();
        let _ = collection1.merge_delta_data(collection2).unwrap();

        assert_eq!(collection1, expected_collection);
    }
}

fn make_create_modify_delete_collections() -> ThreeCollections {
    let mut collection1 = DeltaDataCollection::new();
    let _ = collection1
        .merge_delta_data_element(1, DataDelta::Create(Box::new('a')))
        .unwrap()
        .unwrap();

    let mut collection2 = DeltaDataCollection::new();
    let _ = collection2
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    let _ = collection3
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('b')))
        .unwrap()
        .unwrap();

    (collection1, collection2, collection3)
}
