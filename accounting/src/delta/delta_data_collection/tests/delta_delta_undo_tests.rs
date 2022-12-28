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

use DataDelta::{Create, Delete, Modify};

use rstest::rstest;

type ThreeCollections = (
    DeltaDataCollection<i32, char>,
    DeltaDataCollection<i32, char>,
    DeltaDataCollection<i32, char>,
);

#[rstest]
#[case(make_collections_with_undo(Create('a'), Modify('a', 'b')))]
#[case(make_collections_with_undo(Modify('a', 'b'), Modify('b', 'c')))]
#[case(make_collections_with_undo(Modify('a', 'b'), Delete('b')))]
#[case(make_collections_with_undo(Delete('a'), Create('b')))]
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
        let (mut collection1, collection2, collection3) =
            make_collections_with_undo(DataDelta::Create('a'), DataDelta::Delete('a'));

        let _ = collection1.merge_delta_data(collection2).unwrap();
        let _ = collection1.merge_delta_data(collection3).unwrap();

        let expected_collection = DeltaDataCollection::from_iter(
            [(
                1,
                DeltaMapElement::DeltaUndo(DataDeltaUndo(DataDelta::Create('a'))),
            )]
            .into_iter(),
        );
        assert_eq!(collection1, expected_collection);
    }

    {
        // Create(a) + (Delete(a) + Undo) = Create(a)
        let (mut collection1, mut collection2, collection3) =
            make_collections_with_undo(DataDelta::Create('a'), DataDelta::Delete('a'));
        let expected_collection = collection1.clone();

        let _ = collection2.merge_delta_data(collection3).unwrap();
        let _ = collection1.merge_delta_data(collection2).unwrap();

        assert_eq!(collection1, expected_collection);
    }
}

fn make_collections_with_undo(
    delta1: DataDelta<char>,
    delta2: DataDelta<char>,
) -> ThreeCollections {
    let collection1 = DeltaDataCollection::from_iter([(1, delta1)].into_iter());

    let mut collection2 = DeltaDataCollection::new();
    let undo = collection2.merge_delta_data_element(1, delta2).unwrap().unwrap();

    let collection3 =
        DeltaDataCollection::from_iter([(1, DeltaMapElement::DeltaUndo(undo))].into_iter());

    (collection1, collection2, collection3)
}
