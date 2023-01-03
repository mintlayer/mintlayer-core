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

use DataDelta::Modify;

use rstest::rstest;

type ThreeCollections = (
    DeltaDataCollection<i32, char>,
    DeltaDataCollection<i32, char>,
    DeltaDataCollection<i32, char>,
);

#[rstest]
#[rustfmt::skip]
#[case(Modify(None,      Some('a')), Modify(Some('a'), None))]
#[case(Modify(None,      Some('a')), Modify(Some('a'), Some('b')))]
#[case(Modify(Some('a'), Some('b')), Modify(Some('b'), Some('c')))]
#[case(Modify(Some('a'), Some('b')), Modify(Some('b'), None))]
#[case(Modify(Some('a'), None),      Modify(None,      Some('b')))]
fn delta_delta_undo_associativity(
    #[case] delta1: DataDelta<char>,
    #[case] delta2: DataDelta<char>,
) {
    {
        // (Delta1 + Delta2) + Undo = Delta1
        // every delta goes into separate collection
        let (mut collection1, collection2, collection3) =
            make_collections_with_undo(delta1.clone(), delta2.clone());
        let expected_collection = collection1.clone();

        let _ = collection1.merge_delta_data(collection2).unwrap();
        let _ = collection1.merge_delta_data(collection3).unwrap();

        assert_eq!(collection1, expected_collection);
    }

    {
        // Delta1 + (Delta2 + Undo) = Delta1
        // every delta goes into separate collection
        let (mut collection1, mut collection2, collection3) =
            make_collections_with_undo(delta1.clone(), delta2.clone());
        let expected_collection = collection1.clone();

        let _ = collection2.merge_delta_data(collection3).unwrap();
        let _ = collection1.merge_delta_data(collection2).unwrap();

        assert_eq!(collection1, expected_collection);
    }

    {
        // (Delta1 + Delta2) + Undo = Delta1
        // every delta is applied to the same collection
        let mut collection = DeltaDataCollection::new();
        let _ = collection.merge_delta_data_element(1, delta1).unwrap();
        let expected_collection = collection.clone();

        let undo = collection.merge_delta_data_element(1, delta2).unwrap().unwrap();
        collection.undo_merge_delta_data_element(1, undo).unwrap();

        assert_eq!(collection, expected_collection);
    }
}

fn make_collections_with_undo(
    delta1: DataDelta<char>,
    delta2: DataDelta<char>,
) -> ThreeCollections {
    let collection1 = DeltaDataCollection::from_iter([(1, delta1)]);

    let mut collection2 = DeltaDataCollection::new();
    let undo = collection2.merge_delta_data_element(1, delta2).unwrap().unwrap();

    let collection3 = DeltaDataCollection::from_iter([(1, DeltaMapElement::DeltaUndo(undo))]);

    (collection1, collection2, collection3)
}
