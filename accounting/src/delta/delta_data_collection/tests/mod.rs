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

use proptest::prelude::*;
use rstest::rstest;

mod delta_delta_delta_tests;
mod delta_delta_undo_tests;
mod delta_delta_undo_undo_tests;

impl<T: Arbitrary + Clone + 'static> Arbitrary for DataDelta<T> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let none = Just(DataDelta {
            old: None,
            new: None,
        });
        let none_some = any::<T>().prop_map(|v| DataDelta {
            old: None,
            new: Some(v),
        });
        let some_none = any::<T>().prop_map(|v| DataDelta {
            old: Some(v),
            new: None,
        });
        let some_some = (any::<T>(), any::<T>()).prop_map(|(old, new)| DataDelta {
            old: Some(old),
            new: Some(new),
        });
        prop_oneof![none, none_some, some_none, some_some].boxed()
    }
}

fn new_delta<T: Clone>(prev: Option<T>, next: Option<T>) -> DataDelta<T> {
    DataDelta::new(prev, next)
}

#[rstest]
#[rustfmt::skip]
#[case(new_delta(None, None),           new_delta(None, None),           Ok(new_delta(None, None)))]
#[case(new_delta(None, None),           new_delta(None, Some('a')),      Ok(new_delta(None, Some('a'))))]
#[case(new_delta(None, None),           new_delta(Some('a'), None),      Err(Error::DeltaDataMismatch))]
#[case(new_delta(None, None),           new_delta(Some('a'), Some('b')), Err(Error::DeltaDataMismatch))]
#[case(new_delta(None, Some('a')),      new_delta(None, None),           Err(Error::DeltaDataMismatch))]
#[case(new_delta(None, Some('a')),      new_delta(None, Some('b')),      Err(Error::DeltaDataMismatch))]
#[case(new_delta(None, Some('a')),      new_delta(Some('a'), None),      Ok(new_delta(None, None)))]
#[case(new_delta(None, Some('a')),      new_delta(Some('a'), Some('b')), Ok(new_delta(None, Some('b'))))]
#[case(new_delta(None, Some('a')),      new_delta(Some('b'), Some('c')), Err(Error::DeltaDataMismatch))]
#[case(new_delta(Some('a'), None),      new_delta(None, None),           Ok(new_delta(Some('a'), None)))]
#[case(new_delta(Some('a'), None),      new_delta(None, Some('c')),      Ok(new_delta(Some('a'), Some('c'))))]
#[case(new_delta(Some('a'), None),      new_delta(Some('b'), None),      Err(Error::DeltaDataMismatch))]
#[case(new_delta(Some('a'), None),      new_delta(Some('b'), Some('c')), Err(Error::DeltaDataMismatch))]
#[case(new_delta(Some('a'), Some('b')), new_delta(None, None),           Err(Error::DeltaDataMismatch))]
#[case(new_delta(Some('a'), Some('b')), new_delta(None, Some('c')),      Err(Error::DeltaDataMismatch))]
#[case(new_delta(Some('a'), Some('b')), new_delta(Some('b'), None),      Ok(new_delta(Some('a'), None)))]
#[case(new_delta(Some('a'), Some('b')), new_delta(Some('b'), Some('c')), Ok(new_delta(Some('a'), Some('c'))))]
#[case(new_delta(Some('a'), Some('b')), new_delta(Some('c'), Some('d')), Err(Error::DeltaDataMismatch))]
fn test_combine_deltas(#[case] delta1: DataDelta<char>, #[case] delta2: DataDelta<char>, #[case] result: Result<DataDelta<char>,Error> ) {
    assert_eq!(combine_delta_data(delta1, delta2), result);
}

#[rstest]
#[case(new_delta(None, None))]
#[case(new_delta(None, Some('a')))]
#[case(new_delta(Some('a'), None))]
#[case(new_delta(Some('a'), Some('a')))]
#[case(new_delta(Some('a'), Some('b')))]
fn test_delta_inversion(#[case] delta: DataDelta<char>) {
    // (Delta + Undo) + Delta = Delta
    let result = combine_delta_data(
        combine_delta_data(delta.clone(), delta.clone().invert().consume()).unwrap(),
        delta.clone(),
    )
    .unwrap();
    assert_eq!(result, delta);
}

#[rstest]
#[rustfmt::skip]
#[case(new_delta(None, Some('a')),      new_delta(Some('a'), Some('b')))]
#[case(new_delta(None, Some('a')),      new_delta(Some('a'), None))]
#[case(new_delta(Some('a'), None),      new_delta(None, Some('b')))]
#[case(new_delta(Some('a'), None),      new_delta(None, Some('a')))]
#[case(new_delta(Some('a'), Some('b')), new_delta(Some('b'), None))]
#[case(new_delta(Some('a'), Some('b')), new_delta(Some('b'), Some('c')))]
#[case(new_delta(Some('a'), Some('b')), new_delta(Some('b'), Some('a')))]
fn test_delta_undo(#[case] delta1: DataDelta<char>, #[case] delta2: DataDelta<char>) {
    // (Delta1 + Delta2) + Undo(Delta2) = Delta1
    let result = combine_delta_data(
        combine_delta_data(delta1.clone(), delta2.clone()).unwrap(),
        delta2.invert().consume(),
    ).unwrap();
    assert_eq!(delta1, result);
}

#[rstest]
#[case(new_delta(None, None))]
#[case(new_delta(None, Some('a')))]
#[case(new_delta(Some('a'), None))]
#[case(new_delta(Some('a'), Some('b')))]
fn merge_delta_into_empty_collection(#[case] delta: DataDelta<char>) {
    let mut collection: DeltaDataCollection<i32, char> = DeltaDataCollection::new();
    collection.merge_delta_data_element(0, delta.clone()).unwrap();

    assert_eq!(collection.data.len(), 1);
    assert_eq!(
        collection.data.into_iter().next().unwrap().1.consume(),
        delta
    );
}

#[rstest]
#[case(new_delta(None, None))]
#[case(new_delta(None, Some('a')))]
#[case(new_delta(Some('a'), None))]
#[case(new_delta(Some('a'), Some('b')))]
fn merge_delta_undo_into_empty_collection(#[case] delta: DataDelta<char>) {
    let mut collection: DeltaDataCollection<i32, char> = DeltaDataCollection::new();
    collection
        .undo_merge_delta_data_element(0, DataDeltaUndo::new(delta.clone()))
        .unwrap();

    assert_eq!(collection.data.len(), 1);
    assert_eq!(
        collection.data.into_iter().next().unwrap().1.consume(),
        delta
    );
}

#[rstest]
#[rustfmt::skip]
#[case(new_delta(None, Some('a')),      new_delta(Some('a'), None))]
#[case(new_delta(None, Some('a')),      new_delta(Some('a'), Some('b')))]
#[case(new_delta(Some('a'), None),      new_delta(None, None))]
#[case(new_delta(Some('a'), None),      new_delta(None, Some('c')))]
#[case(new_delta(Some('a'), Some('b')), new_delta(Some('b'), None))]
#[case(new_delta(Some('a'), Some('b')), new_delta(Some('b'), Some('c')))]
fn delta_over_undo_is_an_error(#[case] delta1: DataDelta<char>, #[case] delta2: DataDelta<char>) {
    let mut collection1 = DeltaDataCollection::new();
    let undo = collection1.merge_delta_data_element(1, delta1).unwrap().unwrap();

    let mut collection2 = DeltaDataCollection::new();
    collection2.undo_merge_delta_data_element(1, undo).unwrap();

    let mut collection3 = DeltaDataCollection::new();
    let _ = collection3.merge_delta_data_element(1, delta2).unwrap();

    assert_eq!(
        collection2.merge_delta_data(collection3).unwrap_err(),
        Error::DeltaDataMismatch
    );
}
