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
