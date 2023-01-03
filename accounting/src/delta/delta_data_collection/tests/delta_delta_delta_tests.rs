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

use DataDelta::Modify;

#[rstest]
#[rustfmt::skip]
#[case(Modify(None,      Some('a')), Modify(Some('a'), Some('b')), Modify(Some('b'), Some('c')), Modify(None, Some('c')))]
#[case(Modify(None,      Some('a')), Modify(Some('a'), Some('b')), Modify(Some('b'), None),      Modify(None, None))]
#[case(Modify(None,      Some('a')), Modify(Some('a'), None),      Modify(None,      Some('b')), Modify(None, Some('b')))]
#[case(Modify(Some('a'), None),      Modify(None,      Some('b')), Modify(Some('b'), None),      Modify(Some('a'), None))]
#[case(Modify(Some('a'), None),      Modify(None,      Some('b')), Modify(Some('b'), Some('c')), Modify(Some('a'), Some('c')))]
#[case(Modify(Some('a'), Some('b')), Modify(Some('b'), Some('c')), Modify(Some('c'), None),      Modify(Some('a'), None))]
#[case(Modify(Some('a'), Some('b')), Modify(Some('b'), None),      Modify(None, Some('c')),      Modify(Some('a'), Some('c')))]
fn delta_delta_delta_associativity(
    #[case] delta1: DataDelta<char>,
    #[case] delta2: DataDelta<char>,
    #[case] delta3: DataDelta<char>,
    #[case] expected_delta: DataDelta<char>,
) {
    {
        // (Delta + Delta) + Delta = Delta
        // every delta goes into separate collection
        let mut collection1 = DeltaDataCollection::from_iter([(1, delta1.clone())]);
        let collection2 = DeltaDataCollection::from_iter([(1, delta2.clone())]);
        let collection3 = DeltaDataCollection::from_iter([(1, delta3.clone())]);
        let _ = collection1.merge_delta_data(collection2).unwrap();
        let _ = collection1.merge_delta_data(collection3).unwrap();

        assert_eq!(collection1, DeltaDataCollection::from_iter([(1, expected_delta.clone())]));
    }

    {
        // Delta + (Delta + Delta) = Delta
        // every delta goes into separate collection
        let mut collection1 = DeltaDataCollection::from_iter([(1, delta1.clone())]);
        let mut collection2 = DeltaDataCollection::from_iter([(1, delta2.clone())]);
        let collection3 = DeltaDataCollection::from_iter([(1, delta3.clone())]);
        let _ = collection2.merge_delta_data(collection3).unwrap();
        let _ = collection1.merge_delta_data(collection2).unwrap();

        assert_eq!(collection1, DeltaDataCollection::from_iter([(1, expected_delta.clone())]));
    }

    {
        // (Delta + Delta) + Delta = Delta
        // every delta is applied to the same collection
        let mut collection = DeltaDataCollection::new();
        let _ = collection.merge_delta_data_element(1, delta1).unwrap();
        let _ = collection.merge_delta_data_element(1, delta2).unwrap();
        let _ = collection.merge_delta_data_element(1, delta3).unwrap();

        assert_eq!(collection, DeltaDataCollection::from_iter([(1, expected_delta)]));
    }
}
