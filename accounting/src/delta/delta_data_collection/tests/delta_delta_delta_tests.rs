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

#[rstest]
#[rustfmt::skip]
#[case(new_delta(None,      Some('a')), new_delta(Some('a'), Some('b')), new_delta(Some('b'), Some('c')), new_delta(None, Some('c')))]
#[case(new_delta(None,      Some('a')), new_delta(Some('a'), Some('b')), new_delta(Some('b'), None),      new_delta(None, None))]
#[case(new_delta(None,      Some('a')), new_delta(Some('a'), None),      new_delta(None,      Some('b')), new_delta(None, Some('b')))]
#[case(new_delta(Some('a'), None),      new_delta(None,      Some('b')), new_delta(Some('b'), None),      new_delta(Some('a'), None))]
#[case(new_delta(Some('a'), None),      new_delta(None,      Some('b')), new_delta(Some('b'), Some('c')), new_delta(Some('a'), Some('c')))]
#[case(new_delta(Some('a'), Some('b')), new_delta(Some('b'), Some('c')), new_delta(Some('c'), None),      new_delta(Some('a'), None))]
#[case(new_delta(Some('a'), Some('b')), new_delta(Some('b'), None),      new_delta(None, Some('c')),      new_delta(Some('a'), Some('c')))]
fn delta_delta_delta_associativity(
    #[case] delta1: DataDelta<char>,
    #[case] delta2: DataDelta<char>,
    #[case] delta3: DataDelta<char>,
    #[case] expected_delta: DataDelta<char>,
) {
    let expected_collection = DeltaDataCollection::from_iter([(1, expected_delta)]);

    {
        // (Delta + Delta) + Delta = Delta
        // every delta goes into separate collection
        let mut collection1 = DeltaDataCollection::from_iter([(1, delta1.clone())]);
        let collection2 = DeltaDataCollection::from_iter([(1, delta2.clone())]);
        let collection3 = DeltaDataCollection::from_iter([(1, delta3.clone())]);
        let _ = collection1.merge_delta_data(collection2).unwrap();
        let _ = collection1.merge_delta_data(collection3).unwrap();

        assert_eq!(collection1, expected_collection);
    }

    {
        // Delta + (Delta + Delta) = Delta
        // every delta goes into separate collection
        let mut collection1 = DeltaDataCollection::from_iter([(1, delta1.clone())]);
        let mut collection2 = DeltaDataCollection::from_iter([(1, delta2.clone())]);
        let collection3 = DeltaDataCollection::from_iter([(1, delta3.clone())]);
        let _ = collection2.merge_delta_data(collection3).unwrap();
        let _ = collection1.merge_delta_data(collection2).unwrap();

        assert_eq!(collection1, expected_collection);
    }

    {
        // (Delta + Delta) + Delta = Delta
        // every delta is applied to the same collection
        let mut collection = DeltaDataCollection::new();
        let _ = collection.merge_delta_data_element(1, delta1).unwrap();
        let _ = collection.merge_delta_data_element(1, delta2).unwrap();
        let _ = collection.merge_delta_data_element(1, delta3).unwrap();

        assert_eq!(collection, expected_collection);
    }
}

proptest! {
    // This test verifies that combination of 3 random deltas is associative.
    // Invalid combinations can be generated, but the associativity property
    // doesn't apply for such cases as different Error can be produced depending on the
    // order of operations. So for the sake of this test errors are treated as None
    // and it is only expected that both sequences must produce either the same valid result
    // or both fail with some error.
    #[test]
    fn random_delta_associativity(
        delta1: DataDelta<char>,
        delta2: DataDelta<char>,
        delta3: DataDelta<char>,
    ) {
        let result1 = {
            // (Delta + Delta) + Delta = [Delta|Error]
            let mut collection1 = DeltaDataCollection::from_iter([(1, delta1.clone())]);
            let collection2 = DeltaDataCollection::from_iter([(1, delta2.clone())]);
            let collection3 = DeltaDataCollection::from_iter([(1, delta3.clone())]);
            collection1
                .merge_delta_data(collection2)
                .ok()
                .and_then(|_| collection1.merge_delta_data(collection3).ok().and(Some(collection1)))
        };

        let result2 = {
            // Delta + (Delta + Delta) = [Delta|Error]
            let mut collection1 = DeltaDataCollection::from_iter([(1, delta1)]);
            let mut collection2 = DeltaDataCollection::from_iter([(1, delta2)]);
            let collection3 = DeltaDataCollection::from_iter([(1, delta3)]);
            collection2
                .merge_delta_data(collection3)
                .ok()
                .and_then(|_| collection1.merge_delta_data(collection2).ok().and(Some(collection1)))
        };
        assert_eq!(result1, result2);
    }
}
