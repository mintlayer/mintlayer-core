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

type FourCollections = (
    DeltaDataCollection<i32, char>,
    DeltaDataCollection<i32, char>,
    DeltaDataCollection<i32, char>,
    DeltaDataCollection<i32, char>,
);

fn make_expected_collection(delta: DataDelta<char>) -> DeltaDataCollection<i32, char> {
    DeltaDataCollection::from_iter([(1, delta)])
}

fn make_four_collections(
    delta1: DataDelta<char>,
    delta2: DataDelta<char>,
    delta3: DataDelta<char>,
    delta4: DataDelta<char>,
) -> FourCollections {
    (
        DeltaDataCollection::from_iter([(1, delta1)]),
        DeltaDataCollection::from_iter([(1, delta2)]),
        DeltaDataCollection::from_iter([(1, delta3)]),
        DeltaDataCollection::from_iter([(1, delta4)]),
    )
}

#[rstest]
#[case(
    DeltaDataCollection::new(),
    make_four_collections(Create('a'), Modify('a', 'b'), Modify('b', 'c'), Delete('c'))
)]
#[case(
    make_expected_collection(DataDelta::Create('c')),
    make_four_collections(Create('a'), Modify('a', 'b'), Delete('b'), Create('c'))
)]
#[case(
    DeltaDataCollection::new(),
    make_four_collections(Create('a'), Delete('a'), Create('b'), Delete('b'))
)]
#[case(
    make_expected_collection(DataDelta::Create('c')),
    make_four_collections(Create('a'), Delete('a'), Create('b'), Modify('b', 'c'))
)]
#[case(
    make_expected_collection(DataDelta::Modify('a', 'e')),
    make_four_collections(Modify('a', 'b'), Modify('b', 'c'), Modify('c', 'd'), Modify('d', 'e'))
)]
#[case(
    make_expected_collection(DataDelta::Delete('a')),
    make_four_collections(Modify('a', 'b'), Modify('b', 'c'), Modify('c', 'd'), Delete('d'))
)]
#[case(
    make_expected_collection(DataDelta::Modify('a', 'd')),
    make_four_collections(Modify('a', 'b'), Modify('b', 'c'), Delete('c'), Create('d'))
)]
#[case(
    make_expected_collection(DataDelta::Modify('a', 'e')),
    make_four_collections(Modify('a', 'b'), Delete('b'), Create('d'), Modify('d', 'e'))
)]
#[case(
    make_expected_collection(DataDelta::Delete('a')),
    make_four_collections(Modify('a', 'b'), Delete('b'), Create('d'), Delete('d'))
)]
#[case(
    make_expected_collection(DataDelta::Modify('a', 'c')),
    make_four_collections(Delete('a'), Create('b'), Delete('b'), Create('c'))
)]
#[case(
    make_expected_collection(DataDelta::Modify('a', 'd')),
    make_four_collections(Delete('a'), Create('b'), Modify('b', 'c'), Modify('c', 'd'))
)]
#[case(
    make_expected_collection(DataDelta::Delete('a')),
    make_four_collections(Delete('a'), Create('b'), Modify('b', 'c'), Delete('c'))
)]
fn delta_delta_delta_delta_associativity(
    #[case] expected_collection: DeltaDataCollection<i32, char>,
    #[case] collections: FourCollections,
) {
    {
        // Delta1 + Delta2 + Delta3 + Delta4 = Delta
        let (mut collection1, collection2, collection3, collection4) = collections.clone();
        let _ = collection1.merge_delta_data(collection2).unwrap();
        let _ = collection1.merge_delta_data(collection3).unwrap();
        let _ = collection1.merge_delta_data(collection4).unwrap();

        assert_eq!(collection1, expected_collection);
    }

    {
        // (Delta1 + Delta2) + (Delta3 + Delta4) = Delta
        let (mut collection1, collection2, mut collection3, collection4) = collections.clone();
        let _ = collection1.merge_delta_data(collection2).unwrap();
        let _ = collection3.merge_delta_data(collection4).unwrap();
        let _ = collection1.merge_delta_data(collection3).unwrap();

        assert_eq!(collection1, expected_collection);
    }

    {
        // Delta1 + (Delta2 + Delta3 + Delta4) = Delta
        let (mut collection1, mut collection2, collection3, collection4) = collections.clone();
        let _ = collection2.merge_delta_data(collection3).unwrap();
        let _ = collection2.merge_delta_data(collection4).unwrap();
        let _ = collection1.merge_delta_data(collection2).unwrap();

        assert_eq!(collection1, expected_collection);
    }

    {
        // Delta1 + (Delta2 + (Delta3 + Delta4)) = Delta
        let (mut collection1, mut collection2, mut collection3, collection4) = collections;
        let _ = collection3.merge_delta_data(collection4).unwrap();
        let _ = collection2.merge_delta_data(collection3).unwrap();
        let _ = collection1.merge_delta_data(collection2).unwrap();

        assert_eq!(collection1, expected_collection);
    }
}
