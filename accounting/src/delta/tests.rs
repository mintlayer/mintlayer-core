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

use crate::{combine_data_with_delta, DataDelta, DeltaDataCollection};

use rstest::rstest;

#[rstest]
#[case(None, DataDelta::Create('a'))]
#[case(Some('a'), DataDelta::Delete('a'))]
#[case(Some('a'), DataDelta::Modify('a', 'b'))]
fn data_delta_undo(#[case] origin_data: Option<char>, #[case] delta: DataDelta<char>) {
    let mut collection_with_delta = DeltaDataCollection::new();
    let undo_create = collection_with_delta.merge_delta_data_element(1, delta).unwrap().unwrap();

    let mut collection_with_undo = DeltaDataCollection::new();
    collection_with_undo.undo_merge_delta_data_element(1, undo_create).unwrap();

    // Data + Delta + Undo(Delta) = Data
    {
        let result = combine_data_with_delta(
            origin_data.as_ref(),
            Some(collection_with_delta.data().iter().next().unwrap().1),
        )
        .unwrap();

        let result = combine_data_with_delta(
            result.as_ref(),
            Some(collection_with_undo.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, origin_data);
    }

    // Data + (Delta + Undo(Delta)) = Data + No-op = Data
    {
        let _ = collection_with_delta.merge_delta_data(collection_with_undo).unwrap();
        assert!(collection_with_delta.data().is_empty());
    }
}

#[rstest]
#[rustfmt::skip]
#[case(None,      DataDelta::Create('a'),      DataDelta::Delete('a'),      None)]
#[case(None,      DataDelta::Create('a'),      DataDelta::Modify('a', 'b'), Some('b'))]
#[case(Some('a'), DataDelta::Modify('a', 'b'), DataDelta::Modify('b', 'c'), Some('c'))]
#[case(Some('a'), DataDelta::Modify('a', 'b'), DataDelta::Delete('b'),      None)]
#[case(Some('a'), DataDelta::Delete('a'),      DataDelta::Create('b'),      Some('b'))]
fn data_delta_delta(
    #[case] origin_data: Option<char>,
    #[case] delta1: DataDelta<char>,
    #[case] delta2: DataDelta<char>,
    #[case] expected_data: Option<char>,
) {
    // Data + Delta + Delta = Data
    {
        let collection1 = DeltaDataCollection::from_iter([(1, delta1.clone())]);
        let collection2 = DeltaDataCollection::from_iter([(1, delta2.clone())]);

        let result = combine_data_with_delta(
            origin_data.as_ref(),
            Some(collection1.data().iter().next().unwrap().1),
        )
        .unwrap();

        let result = combine_data_with_delta(
            result.as_ref(),
            Some(collection2.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, expected_data);
    }

    // Data + (Delta + Delta) = Data
    {
        let mut collection1 = DeltaDataCollection::from_iter([(1, delta1)]);
        let collection2 = DeltaDataCollection::from_iter([(1, delta2)]);

        let _ = collection1.merge_delta_data(collection2).unwrap();

        let result = combine_data_with_delta(
            origin_data.as_ref(),
            Some(collection1.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, expected_data);
    }
}

#[rstest]
#[rustfmt::skip]
#[case(None,      DataDelta::Create('a'),      DataDelta::Modify('a', 'b'),  DataDelta::Delete('b'),      None)]
#[case(None,      DataDelta::Create('a'),      DataDelta::Modify('a', 'b'),  DataDelta::Modify('b', 'c'), Some('c'))]
#[case(None,      DataDelta::Create('a'),      DataDelta::Delete('a'),       DataDelta::Create('a'),      Some('a'))]
#[case(Some('a'), DataDelta::Delete('a'),      DataDelta::Create('a'),       DataDelta::Delete('a'),      None)]
#[case(Some('a'), DataDelta::Delete('a'),      DataDelta::Create('a'),       DataDelta::Modify('a', 'b'), Some('b'))]
#[case(Some('a'), DataDelta::Modify('a', 'b'), DataDelta::Delete('a'),       DataDelta::Create('a'),      Some('b'))]
#[case(Some('a'), DataDelta::Modify('a', 'b'), DataDelta::Modify('b', 'c'),  DataDelta::Delete('c'),      None)]
#[case(Some('a'), DataDelta::Modify('a', 'b'), DataDelta::Modify('b', 'c'),  DataDelta::Modify('c', 'd'), Some('d'))]
fn data_delta_delta_delta(
    #[case] origin_data: Option<char>,
    #[case] delta1: DataDelta<char>,
    #[case] delta2: DataDelta<char>,
    #[case] delta3: DataDelta<char>,
    #[case] expected_data: Option<char>,
) {
    // Data + Delta + Delta + Delta = Data
    {
        let collection1 = DeltaDataCollection::from_iter([(1, delta1.clone())]);
        let collection2 = DeltaDataCollection::from_iter([(1, delta2.clone())]);
        let collection3 = DeltaDataCollection::from_iter([(1, delta3.clone())]);

        let result = combine_data_with_delta(
            origin_data.as_ref(),
            Some(collection1.data().iter().next().unwrap().1),
        )
        .unwrap();

        let result = combine_data_with_delta(
            result.as_ref(),
            Some(collection2.data().iter().next().unwrap().1),
        )
        .unwrap();

        let result = combine_data_with_delta(
            result.as_ref(),
            Some(collection3.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, expected_data);
    }

    // Data + (Delta + Delta + Delta) = Data
    {
        let mut collection1 = DeltaDataCollection::from_iter([(1, delta1.clone())]);
        let collection2 = DeltaDataCollection::from_iter([(1, delta2.clone())]);
        let collection3 = DeltaDataCollection::from_iter([(1, delta3.clone())]);

        let _ = collection1.merge_delta_data(collection2).unwrap();
        let _ = collection1.merge_delta_data(collection3).unwrap();

        let result = combine_data_with_delta(
            origin_data.as_ref(),
            Some(collection1.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, expected_data);
    }

    // (Data + Delta) + (Delta + Delta) = Data
    {
        let collection1 = DeltaDataCollection::from_iter([(1, delta1.clone())]);
        let mut collection2 = DeltaDataCollection::from_iter([(1, delta2.clone())]);
        let collection3 = DeltaDataCollection::from_iter([(1, delta3.clone())]);

        let result = combine_data_with_delta(
            origin_data.as_ref(),
            Some(collection1.data().iter().next().unwrap().1),
        )
        .unwrap();

        let _ = collection2.merge_delta_data(collection3).unwrap();

        let result = combine_data_with_delta(
            result.as_ref(),
            Some(collection2.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, expected_data);
    }

    // Data + (Delta + (Delta + Delta)) = Data
    {
        let mut collection1 = DeltaDataCollection::from_iter([(1, delta1)]);
        let mut collection2 = DeltaDataCollection::from_iter([(1, delta2)]);
        let collection3 = DeltaDataCollection::from_iter([(1, delta3)]);

        let _ = collection2.merge_delta_data(collection3).unwrap();
        let _ = collection1.merge_delta_data(collection2).unwrap();

        let result = combine_data_with_delta(
            origin_data.as_ref(),
            Some(collection1.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, expected_data);
    }
}

#[rstest]
#[rustfmt::skip]
#[case(None,      DataDelta::Create('a'),      DataDelta::Modify('a', 'b'), /* Undo(Modify), */ Some('a'))]
#[case(None,      DataDelta::Create('a'),      DataDelta::Delete('a'),      /* Undo(Delete), */ Some('a'))]
#[case(Some('a'), DataDelta::Delete('a'),      DataDelta::Create('a'),      /* Undo(Create), */ None)]
#[case(Some('a'), DataDelta::Modify('a', 'b'), DataDelta::Delete('a'),      /* Undo(Delete), */ Some('b'))]
#[case(Some('a'), DataDelta::Modify('a', 'b'), DataDelta::Modify('b', 'c'), /* Undo(Modify), */ Some('b'))]
fn data_delta_delta_undo(
    #[case] origin_data: Option<char>,
    #[case] delta1: DataDelta<char>,
    #[case] delta2: DataDelta<char>,
    #[case] expected_data: Option<char>,
) {
    // Data + Delta + Delta + Undo = Data
    {

        let collection1 = DeltaDataCollection::from_iter([(1, delta1.clone())]);
        let mut collection2= DeltaDataCollection::new();
        let undo= collection2.merge_delta_data_element(1, delta2.clone()).unwrap().unwrap();
        let mut collection3= DeltaDataCollection::new();
        collection3.undo_merge_delta_data_element(1, undo).unwrap();


        let result = combine_data_with_delta(
            origin_data.as_ref(),
            Some(collection1.data().iter().next().unwrap().1),
        )
        .unwrap();

        let result = combine_data_with_delta(
            result.as_ref(),
            Some(collection2.data().iter().next().unwrap().1),
        )
        .unwrap();

        let result = combine_data_with_delta(
            result.as_ref(),
            Some(collection3.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, expected_data);
    }

    // Data + (Delta + Delta + Undo) = Data
    {
        let mut collection1 = DeltaDataCollection::from_iter([(1, delta1.clone())]);
        let mut collection2= DeltaDataCollection::new();
        let undo= collection2.merge_delta_data_element(1, delta2.clone()).unwrap().unwrap();
        let mut collection3= DeltaDataCollection::new();
        collection3.undo_merge_delta_data_element(1, undo).unwrap();

        let _ = collection1.merge_delta_data(collection2).unwrap();
        let _ = collection1.merge_delta_data(collection3).unwrap();

        let result = combine_data_with_delta(
            origin_data.as_ref(),
            Some(collection1.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, expected_data);
    }

    // (Data + Delta) + (Delta + Delta) = Data
    {
        let collection1 = DeltaDataCollection::from_iter([(1, delta1.clone())]);
        let mut collection2= DeltaDataCollection::new();
        let undo= collection2.merge_delta_data_element(1, delta2.clone()).unwrap().unwrap();
        let mut collection3= DeltaDataCollection::new();
        collection3.undo_merge_delta_data_element(1, undo).unwrap();

        let result = combine_data_with_delta(
            origin_data.as_ref(),
            Some(collection1.data().iter().next().unwrap().1),
        )
        .unwrap();

        let _ = collection2.merge_delta_data(collection3).unwrap();

        let result = combine_data_with_delta(
            result.as_ref(),
            Some(collection2.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, expected_data);
    }

    // Data + (Delta + (Delta + Delta)) = Data
    {
        let mut collection1 = DeltaDataCollection::from_iter([(1, delta1)]);
        let mut collection2= DeltaDataCollection::new();
        let undo= collection2.merge_delta_data_element(1, delta2).unwrap().unwrap();
        let mut collection3= DeltaDataCollection::new();
        collection3.undo_merge_delta_data_element(1, undo).unwrap();

        let _ = collection2.merge_delta_data(collection3).unwrap();
        let _ = collection1.merge_delta_data(collection2).unwrap();

        let result = combine_data_with_delta(
            origin_data.as_ref(),
            Some(collection1.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, expected_data);
    }
}
