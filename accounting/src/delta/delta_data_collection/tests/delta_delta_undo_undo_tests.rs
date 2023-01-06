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

type FourCollections = (
    DeltaDataCollection<i32, char>,
    DeltaDataCollection<i32, char>,
    DeltaDataCollection<i32, char>,
    DeltaDataCollection<i32, char>,
);

fn make_collections_with_undo(delta1: DataDelta<char>, delta2: DataDelta<char>) -> FourCollections {
    let mut collection1 = DeltaDataCollection::new();
    let undo_delta1 = collection1.merge_delta_data_element(1, delta1).unwrap().unwrap();

    let mut collection2 = DeltaDataCollection::new();
    let undo_delta2 = collection2.merge_delta_data_element(1, delta2).unwrap().unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_delta2).unwrap();

    let mut collection4 = DeltaDataCollection::new();
    collection4.undo_merge_delta_data_element(1, undo_delta1).unwrap();

    (collection1, collection2, collection3, collection4)
}

#[rstest]
#[rustfmt::skip]
#[case(new_delta(None,      Some('a')), new_delta(Some('a'), None),      new_delta(None,      None))]
#[case(new_delta(None,      Some('a')), new_delta(Some('a'), Some('b')), new_delta(None,      None))]
#[case(new_delta(Some('a'), Some('b')), new_delta(Some('b'), Some('c')), new_delta(Some('a'), Some('a')))]
#[case(new_delta(Some('a'), Some('b')), new_delta(Some('b'), None),      new_delta(Some('a'), Some('a')))]
#[case(new_delta(Some('a'), None),      new_delta(None,      Some('b')), new_delta(Some('a'), Some('a')))]
fn delta_delta_undo_undo_associativity(
    #[case] delta1: DataDelta<char>,
    #[case] delta2: DataDelta<char>,
    #[case] expected_delta: DataDelta<char>,
) {
    let expected_collection = DeltaDataCollection::from_iter([(1, expected_delta)]);

    {
        // ((Delta1 + Delta2) + Undo1) + Undo2 = Delta
        // every delta goes into separate collection
        let (mut collection1, collection2, collection3, collection4) =
            make_collections_with_undo(delta1.clone(), delta2.clone());
        let _ = collection1.merge_delta_data(collection2).unwrap();
        let _ = collection1.merge_delta_data(collection3).unwrap();
        let _ = collection1.merge_delta_data(collection4).unwrap();

        assert_eq!(collection1, expected_collection);
    }

    {
        // (Delta1 + Delta2) + (Undo1 + Undo2) = Delta
        // every delta goes into separate collection
        let (mut collection1, collection2, mut collection3, collection4) =
            make_collections_with_undo(delta1.clone(), delta2.clone());
        let _ = collection1.merge_delta_data(collection2).unwrap();
        let _ = collection3.merge_delta_data(collection4).unwrap();
        let _ = collection1.merge_delta_data(collection3).unwrap();

        assert_eq!(collection1, expected_collection);
    }

    {
        // Delta1 + ((Delta2 + Undo1) + Undo2) = Delta
        // every delta goes into separate collection
        let (mut collection1, mut collection2, collection3, collection4) =
            make_collections_with_undo(delta1.clone(), delta2.clone());
        let _ = collection2.merge_delta_data(collection3).unwrap();
        let _ = collection2.merge_delta_data(collection4).unwrap();
        let _ = collection1.merge_delta_data(collection2).unwrap();

        assert_eq!(collection1, expected_collection);
    }

    {
        // Delta1 + (Delta2 + (Undo1 + Undo2)) = Delta
        let (mut collection1, mut collection2, mut collection3, collection4) =
            make_collections_with_undo(delta1.clone(), delta2.clone());
        let _ = collection3.merge_delta_data(collection4).unwrap();
        let _ = collection2.merge_delta_data(collection3).unwrap();
        let _ = collection1.merge_delta_data(collection2).unwrap();

        assert_eq!(collection1, expected_collection);
    }

    {
        // ((Delta1 + Delta2) + Undo1) + Undo2 = Delta
        // every delta is applied to the same collection
        let mut collection = DeltaDataCollection::new();
        let undo1 = collection.merge_delta_data_element(1, delta1).unwrap().unwrap();
        let undo2 = collection.merge_delta_data_element(1, delta2).unwrap().unwrap();
        collection.undo_merge_delta_data_element(1, undo2).unwrap();
        collection.undo_merge_delta_data_element(1, undo1).unwrap();

        assert_eq!(collection, expected_collection);
    }
}

proptest! {
    // This test verifies that combination of 2 random deltas and 2 undo is associative.
    // Invalid combinations can be generated, but the associativity property
    // doesn't apply for such cases as different Error can be produced depending on the
    // order of operations. So for the sake of this test errors are treated as None
    // and it is only expected that both sequences must produce either the same valid result
    // or both fail with some error.
    #[test]
    fn random_delta_associativity(delta1: DataDelta<char>, delta2: DataDelta<char>) {
        let result1 = {
            // ((Delta1 + Delta2) + Undo1) + Undo2 = [Delta|Error]
            let (mut collection1, collection2, collection3, collection4) =
                make_collections_with_undo(delta1.clone(), delta2.clone());
            collection1.merge_delta_data(collection2).ok().and_then(|_| {
                collection1
                    .merge_delta_data(collection3)
                    .ok()
                    .and_then(|_| collection1.merge_delta_data(collection4).ok().and(Some(collection1)))
            })
        };

        let result2 = {
            // (Delta1 + Delta2) + (Undo1 + Undo2) = [Delta|Error]
            let (mut collection1, collection2, mut collection3, collection4) =
                make_collections_with_undo(delta1.clone(), delta2.clone());
            collection1.merge_delta_data(collection2).ok().and_then(|_| {
                collection3
                    .merge_delta_data(collection4)
                    .ok()
                    .and_then(|_| collection1.merge_delta_data(collection3).ok().and(Some(collection1)))
            })
        };

        let result3 = {
            // Delta1 + ((Delta2 + Undo1) + Undo2) = [Delta|Error]
            let (mut collection1, mut collection2, collection3, collection4) =
                make_collections_with_undo(delta1.clone(), delta2.clone());
            collection2.merge_delta_data(collection3).ok().and_then(|_| {
                collection2
                    .merge_delta_data(collection4)
                    .ok()
                    .and_then(|_| collection1.merge_delta_data(collection2).ok().and(Some(collection1)))
            })
        };

        let result4 = {
            // Delta1 + (Delta2 + (Undo1 + Undo2)) = [Delta|Error]
            let (mut collection1, mut collection2, mut collection3, collection4) =
                make_collections_with_undo(delta1, delta2);
            collection3.merge_delta_data(collection4).ok().and_then(|_| {
                collection2
                    .merge_delta_data(collection3)
                    .ok()
                    .and_then(|_| collection1.merge_delta_data(collection2).ok().and(Some(collection1)))
            })
        };

        assert_eq!(result1, result2);
        assert_eq!(result1, result3);
        assert_eq!(result1, result4);
    }
}
