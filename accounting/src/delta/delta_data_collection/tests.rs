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

// test function to avoid implementing Eq to compare DataDeltaUndo with DataDelta
fn convert_undo_to_delta<T: Clone>(d: DataDeltaUndo<T>) -> DataDelta<T> {
    match d {
        DataDeltaUndo::Create(d) => DataDelta::Create(d),
        DataDeltaUndo::Modify(d) => DataDelta::Modify(d),
        DataDeltaUndo::Delete(d) => DataDelta::Delete(d),
    }
}

#[test]
#[rustfmt::skip]
fn test_combine_deltas() {
    use DataDelta::{Create, Delete, Modify};

    assert_eq!(combine_deltas(&Create(Box::new('a')), Create(Box::new('b'))),                  Err(Error::DeltaDataCreatedMultipleTimes));
    assert_eq!(combine_deltas(&Create(Box::new('a')), Modify((Box::new('a'), Box::new('b')))), Ok(DataDelta::Create(Box::new('b'))));
    assert_eq!(combine_deltas(&Create(Box::new('a')), Delete(Box::new('a'))),                  Ok(DataDelta::Delete(Box::new('a'))));

    assert_eq!(combine_deltas(&Modify((Box::new('a'), Box::new('b'))), Create(Box::new('c'))),                  Err(Error::DeltaDataCreatedMultipleTimes));
    assert_eq!(combine_deltas(&Modify((Box::new('a'), Box::new('b'))), Modify((Box::new('c'), Box::new('d')))), Ok(DataDelta::Modify((Box::new('a'), Box::new('d')))));
    assert_eq!(combine_deltas(&Modify((Box::new('a'), Box::new('b'))), Delete(Box::new('c'))),                  Ok(DataDelta::Delete(Box::new('c'))));

    assert_eq!(combine_deltas(&Delete(Box::new('a')), Create(Box::new('b'))),                  Ok(DataDelta::Create(Box::new('b'))));
    assert_eq!(combine_deltas(&Delete(Box::new('a')), Modify((Box::new('b'), Box::new('c')))), Err(Error::DeltaDataModifyAfterDelete));
    assert_eq!(combine_deltas(&Delete(Box::new('a')), Delete(Box::new('b'))),                  Err(Error::DeltaDataDeletedMultipleTimes));
}

#[test]
#[rustfmt::skip]
fn test_combine_delta_with_undo() {
    let delta_create = |c| DataDelta::Create(Box::new(c));
    let delta_modify = |c1, c2| DataDelta::Modify((Box::new(c1), Box::new(c2)));
    let delta_delete= |c| DataDelta::Delete(Box::new(c));

    let undo_create = |c| DataDeltaUndo::Create(Box::new(c));
    let undo_modify = |c1,c2| DataDeltaUndo::Modify((Box::new(c1), Box::new(c2)));
    let undo_delete= |c| DataDeltaUndo::Delete(Box::new(c));

    assert_eq!(combine_delta_with_undo(&delta_create('a'),      undo_create('b')),      Ok(undo_create('b')));
    assert_eq!(combine_delta_with_undo(&delta_create('a'),      undo_modify('a', 'b')), Ok(undo_create('b')));
    assert_eq!(combine_delta_with_undo(&delta_create('a'),      undo_delete('a')),      Ok(undo_delete('a')));

    assert_eq!(combine_delta_with_undo(&delta_modify('a', 'b'), undo_create('c')),      Ok(undo_modify('a', 'c')));
    assert_eq!(combine_delta_with_undo(&delta_modify('a', 'b'), undo_modify('c', 'd')), Ok(undo_modify('a', 'd')));
    assert_eq!(combine_delta_with_undo(&delta_modify('a', 'b'), undo_delete('b')),      Ok(undo_delete('b')));

    assert_eq!(combine_delta_with_undo(&delta_delete('a'),      undo_create('b')),      Ok(undo_create('b')));
    assert_eq!(combine_delta_with_undo(&delta_delete('a'),      undo_modify('a', 'b')), Err(Error::DeltaDataModifyAfterDelete));
    assert_eq!(combine_delta_with_undo(&delta_delete('a'),      undo_delete('b')),      Ok(undo_delete('b')));
}

#[test]
#[rustfmt::skip]
fn test_combine_undos() {
    let create = |c| DataDeltaUndo::Create(Box::new(c));
    let modify = |c1,c2| DataDeltaUndo::Modify((Box::new(c1), Box::new(c2)));
    let delete= |c| DataDeltaUndo::Delete(Box::new(c));

    assert_eq!(combine_undos(&create('a'),      create('b')),      Err(Error::DeltaDataDeletedMultipleTimes));
    assert_eq!(combine_undos(&create('a'),      modify('a', 'b')), Ok(create('b')));
    assert_eq!(combine_undos(&create('a'),      delete('a')),      Ok(delete('a')));

    assert_eq!(combine_undos(&modify('a', 'b'), create('c')),      Ok(modify('a', 'c')));
    assert_eq!(combine_undos(&modify('a', 'b'), modify('c', 'd')), Ok(modify('a', 'd')));
    assert_eq!(combine_undos(&modify('a', 'b'), delete('b')),      Ok(delete('b')));

    assert_eq!(combine_undos(&delete('a'),      create('b')),      Ok(create('b')));
    assert_eq!(combine_undos(&delete('a'),      modify('a', 'b')), Err(Error::DeltaDataModifyAfterDelete));
    assert_eq!(combine_undos(&delete('a'),      delete('b')),      Err(Error::DeltaDataCreatedMultipleTimes));
}

#[test]
#[rustfmt::skip]
fn test_create_delta_undo() {
    let delta_create = |c| DataDelta::Create(Box::new(c));
    let delta_modify = |c1, c2| DataDelta::Modify((Box::new(c1), Box::new(c2)));
    let delta_delete= |c| DataDelta::Delete(Box::new(c));

    let undo_create = |c| DataDeltaUndo::Create(Box::new(c));
    let undo_modify = |c1,c2| DataDeltaUndo::Modify((Box::new(c1), Box::new(c2)));
    let undo_delete= |c| DataDeltaUndo::Delete(Box::new(c));

    assert_eq!(create_undo_delta(Some(&delta_create('a')),      delta_create('b')),      Err(Error::DeltaDataCreatedMultipleTimes));
    assert_eq!(create_undo_delta(Some(&delta_create('a')),      delta_modify('a', 'b')), Ok(undo_modify('b', 'a')));
    assert_eq!(create_undo_delta(Some(&delta_create('a')),      delta_delete('a')),      Ok(undo_create('a')));

    assert_eq!(create_undo_delta(Some(&delta_modify('a', 'b')), delta_create('c') ),     Err(Error::DeltaDataCreatedMultipleTimes));
    assert_eq!(create_undo_delta(Some(&delta_modify('a', 'b')), delta_modify('b', 'c')), Ok(undo_modify('c', 'b')));
    assert_eq!(create_undo_delta(Some(&delta_modify('a', 'b')), delta_delete('b') ),     Ok(undo_create('b')));

    assert_eq!(create_undo_delta(Some(&delta_delete('a')),      delta_create('a')),      Ok(undo_delete('a')));
    assert_eq!(create_undo_delta(Some(&delta_delete('a')),      delta_modify('a', 'b')), Err(Error::DeltaDataModifyAfterDelete));
    assert_eq!(create_undo_delta(Some(&delta_delete('a')),      delta_delete('a')),      Err(Error::DeltaDataDeletedMultipleTimes));

    assert_eq!(create_undo_delta(None, delta_create('a')),      Ok(undo_delete('a')));
    assert_eq!(create_undo_delta(None, delta_modify('a', 'b')), Ok(undo_modify('b', 'a')));
    assert_eq!(create_undo_delta(None, delta_delete('a')),      Ok(undo_create('a')));
}

// Test `create_undo_delta` function rule:
// "returns a delta that if applied to the result of merge(delta1,delta2) has the same effect as original delta1"
//
// Note: it has one exception that is tested in `test_create_delta_undo_symmetry_exception`
#[test]
fn test_create_delta_undo_symmetry() {
    let check_undo = |delta1, delta2: DataDelta<char>| {
        let combine_result = combine_deltas(&delta1, delta2.clone()).unwrap();
        let undo = create_undo_delta(Some(&delta1), delta2).unwrap();
        let undo_result = combine_delta_with_undo(&combine_result, undo).unwrap();

        assert_eq!(delta1, convert_undo_to_delta(undo_result));
    };

    check_undo(
        DataDelta::Create(Box::new('a')),
        DataDelta::Modify((Box::new('a'), Box::new('b'))),
    );
    check_undo(
        DataDelta::Create(Box::new('a')),
        DataDelta::Delete(Box::new('a')),
    );

    check_undo(
        DataDelta::Modify((Box::new('a'), Box::new('b'))),
        DataDelta::Modify((Box::new('b'), Box::new('c'))),
    );

    check_undo(
        DataDelta::Delete(Box::new('a')),
        DataDelta::Create(Box::new('a')),
    );
}

#[test]
fn test_create_delta_undo_symmetry_exception() {
    let delta1 = DataDelta::Modify((Box::new('a'), Box::new('b')));
    let delta2 = DataDelta::Delete(Box::new('b'));

    let combine_result = combine_deltas(&delta1, delta2.clone()).unwrap();
    let undo = create_undo_delta(Some(&delta1), delta2).unwrap();
    let undo_result = combine_delta_with_undo(&combine_result, undo).unwrap();

    // Undo(Create(`b`)) has same effect as Undo(Modify(_, 'b'))
    let expected_result = DataDelta::Create(Box::new('b'));
    assert_eq!(expected_result, convert_undo_to_delta(undo_result));
}

#[test]
fn test_merge_collections() {
    // This test check all valid combinations:
    //    collection1 - collection2
    //    -------------------------
    //         Create - Modify
    //         Create - Delete
    //         Modify - Modify
    //         Modify - Delete
    //         Delete - Create
    //         Create - None
    //         Modify - None
    //         Delete - None
    //         None   - Create
    //         None   - Modify
    //         None   - Delete

    let mut collection1 = DeltaDataCollection::from_iter(
        [
            (1, DataDelta::Create(Box::new('a'))),
            (2, DataDelta::Create(Box::new('b'))),
            (3, DataDelta::Modify((Box::new('a'), Box::new('c')))),
            (4, DataDelta::Modify((Box::new('a'), Box::new('d')))),
            (5, DataDelta::Delete(Box::new('e'))),
            (6, DataDelta::Create(Box::new('f'))),
            (7, DataDelta::Modify((Box::new('a'), Box::new('g')))),
            (8, DataDelta::Delete(Box::new('h'))),
        ]
        .into_iter(),
    );

    let collection2 = DeltaDataCollection::from_iter(
        [
            (1, DataDelta::Modify((Box::new('a'), Box::new('i')))),
            (2, DataDelta::Delete(Box::new('b'))),
            (3, DataDelta::Modify((Box::new('c'), Box::new('j')))),
            (4, DataDelta::Delete(Box::new('d'))),
            (5, DataDelta::Create(Box::new('e'))),
            (9, DataDelta::Create(Box::new('m'))),
            (10, DataDelta::Modify((Box::new('a'), Box::new('n')))),
            (11, DataDelta::Delete(Box::new('o'))),
        ]
        .into_iter(),
    );

    let expected_data_after_merge = BTreeMap::from_iter(
        [
            (1, DeltaMapElement::Delta(DataDelta::Create(Box::new('i')))),
            (2, DeltaMapElement::Delta(DataDelta::Delete(Box::new('b')))),
            (
                3,
                DeltaMapElement::Delta(DataDelta::Modify((Box::new('a'), Box::new('j')))),
            ),
            (4, DeltaMapElement::Delta(DataDelta::Delete(Box::new('d')))),
            (5, DeltaMapElement::Delta(DataDelta::Create(Box::new('e')))),
            (6, DeltaMapElement::Delta(DataDelta::Create(Box::new('f')))),
            (
                7,
                DeltaMapElement::Delta(DataDelta::Modify((Box::new('a'), Box::new('g')))),
            ),
            (8, DeltaMapElement::Delta(DataDelta::Delete(Box::new('h')))),
            (9, DeltaMapElement::Delta(DataDelta::Create(Box::new('m')))),
            (
                10,
                DeltaMapElement::Delta(DataDelta::Modify((Box::new('a'), Box::new('n')))),
            ),
            (11, DeltaMapElement::Delta(DataDelta::Delete(Box::new('o')))),
        ]
        .into_iter(),
    );

    let undo_data = collection1.merge_delta_data(collection2).unwrap();
    assert_eq!(collection1.data, expected_data_after_merge);

    let expected_data_after_undo = BTreeMap::from_iter(
        [
            (
                1,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('a'))),
            ),
            (
                2,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('b'))),
            ),
            (
                3,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Modify((Box::new('a'), Box::new('c')))),
            ),
            (
                4,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('d'))),
            ),
            (
                5,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Delete(Box::new('e'))),
            ),
            (6, DeltaMapElement::Delta(DataDelta::Create(Box::new('f')))),
            (
                7,
                DeltaMapElement::Delta(DataDelta::Modify((Box::new('a'), Box::new('g')))),
            ),
            (8, DeltaMapElement::Delta(DataDelta::Delete(Box::new('h')))),
            (
                9,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Delete(Box::new('m'))),
            ),
            (
                10,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Modify((Box::new('a'), Box::new('a')))),
            ),
            (
                11,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('o'))),
            ),
        ]
        .into_iter(),
    );
    collection1.undo_merge_delta_data(undo_data).unwrap();
    assert_eq!(collection1.data, expected_data_after_undo);
}

#[test]
fn test_undo_nonexisting_delta() {
    {
        let mut collection: DeltaDataCollection<i32, char> = DeltaDataCollection::new();
        collection
            .undo_merge_delta_data_element(0, DataDeltaUndo::Create(Box::new('a')))
            .unwrap();
        let expected_data = BTreeMap::from_iter(
            [(
                0,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('a'))),
            )]
            .into_iter(),
        );
        assert_eq!(collection.data, expected_data);
    }

    {
        let mut collection: DeltaDataCollection<i32, char> = DeltaDataCollection::new();
        collection
            .undo_merge_delta_data_element(
                0,
                DataDeltaUndo::Modify((Box::new('a'), (Box::new('b')))),
            )
            .unwrap();
        let expected_data = BTreeMap::from_iter(
            [(
                0,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Modify((Box::new('a'), Box::new('b')))),
            )]
            .into_iter(),
        );
        assert_eq!(collection.data, expected_data);
    }

    {
        let mut collection: DeltaDataCollection<i32, char> = DeltaDataCollection::new();
        collection
            .undo_merge_delta_data_element(0, DataDeltaUndo::Delete(Box::new('a')))
            .unwrap();
        let expected_data = BTreeMap::from_iter(
            [(
                0,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Delete(Box::new('a'))),
            )]
            .into_iter(),
        );
        assert_eq!(collection.data, expected_data);
    }
}

#[test]
fn create_delete_in_collection_then_undo_delete_in_new_collection_then_merge() {
    let mut collection1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());
    let expected_data = BTreeMap::from_iter(
        [(
            1,
            DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('a'))),
        )]
        .into_iter(),
    );

    let mut collection2 = DeltaDataCollection::new();
    let undo_delete = collection2
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('a')))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_delete).unwrap();

    let _ = collection2.merge_delta_data(collection3).unwrap();
    let _ = collection1.merge_delta_data(collection2).unwrap();
    assert_eq!(collection1.data, expected_data);
}

#[test]
fn create_delete_merge_undo() {
    let mut collection1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());
    let expected_data = BTreeMap::from_iter(
        [(
            1,
            DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('a'))),
        )]
        .into_iter(),
    );

    let mut collection2 = DeltaDataCollection::new();
    let undo_delete = collection2
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('a')))
        .unwrap()
        .unwrap();
    let _ = collection1.merge_delta_data(collection2).unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_delete).unwrap();

    let _ = collection1.merge_delta_data(collection3).unwrap();
    assert_eq!(collection1.data, expected_data);
}

#[test]
fn create_modify_undo_merge() {
    let mut collection1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());
    let expected_data = BTreeMap::from_iter(
        [(
            1,
            DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('a'))),
        )]
        .into_iter(),
    );

    let mut collection2 = DeltaDataCollection::new();
    let undo_modify = collection2
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_modify).unwrap();

    let _ = collection2.merge_delta_data(collection3).unwrap();
    let _ = collection1.merge_delta_data(collection2).unwrap();
    assert_eq!(collection1.data, expected_data);
}

#[test]
fn create_modify_merge_undo() {
    let mut collection1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());
    let expected_data = BTreeMap::from_iter(
        [(
            1,
            DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('a'))),
        )]
        .into_iter(),
    );

    let mut collection2 = DeltaDataCollection::new();
    let undo_modify = collection2
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    let _ = collection1.merge_delta_data(collection2).unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_modify).unwrap();

    let _ = collection1.merge_delta_data(collection3).unwrap();
    assert_eq!(collection1.data, expected_data);
}

#[test]
fn create_modify_merge_undo2() {
    let mut collection1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());
    let expected_data = BTreeMap::from_iter(
        [(
            1,
            DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('a'))),
        )]
        .into_iter(),
    );

    let collection2 = DeltaDataCollection::from_iter(
        [(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))].into_iter(),
    );

    let undo = collection1.merge_delta_data(collection2).unwrap();

    collection1.undo_merge_delta_data(undo).unwrap();

    assert_eq!(collection1.data, expected_data);
}

fn make_collections() -> (
    DeltaDataCollection<i32, char>,
    DeltaDataCollection<i32, char>,
    DeltaDataCollection<i32, char>,
    DeltaDataCollection<i32, char>,
) {
    let mut collection1 = DeltaDataCollection::new();
    let undo_create = collection1
        .merge_delta_data_element(1, DataDelta::Create(Box::new('a')))
        .unwrap()
        .unwrap();

    let mut collection2 = DeltaDataCollection::new();
    let undo_delete = collection2
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('a')))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_delete).unwrap();

    let mut collection4 = DeltaDataCollection::new();
    collection4.undo_merge_delta_data_element(1, undo_create).unwrap();

    (collection1, collection2, collection3, collection4)
}

#[test]
fn create_delete_undo_undo() {
    let (mut collection1, mut collection2, mut collection3, collection4) = make_collections();

    {
        let _ = collection3.merge_delta_data(collection4).unwrap();
        let _ = collection2.merge_delta_data(collection3).unwrap();
        let _ = collection1.merge_delta_data(collection2).unwrap();

        let expected_data = BTreeMap::from_iter(
            [(
                1,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Delete(Box::new('a'))),
            )]
            .into_iter(),
        );
        assert_eq!(collection1.data, expected_data);
    }

    let (mut collection1, mut collection2, collection3, collection4) = make_collections();

    {
        let _ = collection2.merge_delta_data(collection3).unwrap();
        let _ = collection2.merge_delta_data(collection4).unwrap();
        let _ = collection1.merge_delta_data(collection2).unwrap();

        let expected_data = BTreeMap::from_iter(
            [(
                1,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Delete(Box::new('a'))),
            )]
            .into_iter(),
        );
        assert_eq!(collection1.data, expected_data);
    }

    let (mut collection1, collection2, collection3, collection4) = make_collections();

    {
        let _ = collection1.merge_delta_data(collection2).unwrap();
        let _ = collection1.merge_delta_data(collection3).unwrap();
        let _ = collection1.merge_delta_data(collection4).unwrap();

        let expected_data = BTreeMap::from_iter(
            [(
                1,
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Delete(Box::new('a'))),
            )]
            .into_iter(),
        );
        assert_eq!(collection1.data, expected_data);
    }
}

#[test]
fn delete_create_undo_undo() {
    let mut collection1 = DeltaDataCollection::new();
    let undo_delete = collection1
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('a')))
        .unwrap()
        .unwrap();

    let mut collection2 = DeltaDataCollection::new();
    let undo_create = collection2
        .merge_delta_data_element(1, DataDelta::Create(Box::new('b')))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_create).unwrap();

    let mut collection4 = DeltaDataCollection::new();
    collection4.undo_merge_delta_data_element(1, undo_delete).unwrap();

    let _ = collection3.merge_delta_data(collection4).unwrap();
    let _ = collection2.merge_delta_data(collection3).unwrap();
    let _ = collection1.merge_delta_data(collection2).unwrap();

    let expected_data = BTreeMap::from_iter(
        [(
            1,
            DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('a'))),
        )]
        .into_iter(),
    );
    assert_eq!(collection1.data, expected_data);
}

#[test]
fn delete_modify_undo_undo_fail() {
    let mut collection1 = DeltaDataCollection::new();
    let undo_delete = collection1
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('a')))
        .unwrap()
        .unwrap();

    let mut collection2 = DeltaDataCollection::new();
    let undo_modify = collection2
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_modify).unwrap();

    let mut collection4 = DeltaDataCollection::new();
    collection4.undo_merge_delta_data_element(1, undo_delete).unwrap();

    let _ = collection3.merge_delta_data(collection4).unwrap();
    let _ = collection2.merge_delta_data(collection3).unwrap();
    assert_eq!(
        collection1.merge_delta_data(collection2).unwrap_err(),
        Error::DeltaDataModifyAfterDelete
    );
}

#[test]
fn create_modify_undo_undo() {
    let mut collection1 = DeltaDataCollection::new();
    let undo_create = collection1
        .merge_delta_data_element(1, DataDelta::Create(Box::new('a')))
        .unwrap()
        .unwrap();

    let mut collection2 = DeltaDataCollection::new();
    let undo_modify = collection2
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_modify).unwrap();

    let mut collection4 = DeltaDataCollection::new();
    collection4.undo_merge_delta_data_element(1, undo_create).unwrap();

    let _ = collection3.merge_delta_data(collection4).unwrap();
    let _ = collection2.merge_delta_data(collection3).unwrap();
    let _ = collection1.merge_delta_data(collection2).unwrap();

    let expected_data = BTreeMap::from_iter(
        [(
            1,
            DeltaMapElement::DeltaUndo(DataDeltaUndo::Delete(Box::new('a'))),
        )]
        .into_iter(),
    );
    assert_eq!(collection1.data, expected_data);
}

#[test]
fn create_modify_delete_undo_merge() {
    let mut collection1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());

    let mut collection2 = DeltaDataCollection::new();
    let _ = collection2
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    let undo_delete = collection3
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('b')))
        .unwrap()
        .unwrap();

    let mut collection4 = DeltaDataCollection::new();
    collection4.undo_merge_delta_data_element(1, undo_delete).unwrap();

    let _ = collection3.merge_delta_data(collection4).unwrap();
    let _ = collection2.merge_delta_data(collection3).unwrap();
    let _ = collection1.merge_delta_data(collection2).unwrap();

    let expected_data = BTreeMap::from_iter(
        [(
            1,
            DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('b'))),
        )]
        .into_iter(),
    );
    assert_eq!(collection1.data, expected_data);
}

#[test]
fn create_modify_delete_undo_undo_merge() {
    let mut collection1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());

    let mut collection2 = DeltaDataCollection::new();
    let undo_modify = collection2
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    let undo_delete = collection3
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('b')))
        .unwrap()
        .unwrap();

    let mut collection4 = DeltaDataCollection::new();
    collection4.undo_merge_delta_data_element(1, undo_delete).unwrap();

    let mut collection5 = DeltaDataCollection::new();
    collection5.undo_merge_delta_data_element(1, undo_modify).unwrap();

    let _ = collection4.merge_delta_data(collection5).unwrap();
    let _ = collection3.merge_delta_data(collection4).unwrap();
    let _ = collection2.merge_delta_data(collection3).unwrap();
    let _ = collection1.merge_delta_data(collection2).unwrap();

    let expected_data = BTreeMap::from_iter(
        [(
            1,
            DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('a'))),
        )]
        .into_iter(),
    );
    assert_eq!(collection1.data, expected_data);
}

#[test]
fn create_modify_modify_undo_merge() {
    let mut collection1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());

    let mut collection2 = DeltaDataCollection::new();
    let _ = collection2
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    let undo_modify = collection3
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('b'), Box::new('c'))))
        .unwrap()
        .unwrap();

    let mut collection4 = DeltaDataCollection::new();
    collection4.undo_merge_delta_data_element(1, undo_modify).unwrap();

    let _ = collection3.merge_delta_data(collection4).unwrap();
    let _ = collection2.merge_delta_data(collection3).unwrap();
    let _ = collection1.merge_delta_data(collection2).unwrap();

    let expected_data = BTreeMap::from_iter(
        [(
            1,
            DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('b'))),
        )]
        .into_iter(),
    );
    assert_eq!(collection1.data, expected_data);
}

#[test]
fn create_modify_modify_merge_undo_undo_merge() {
    let mut collection1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());

    let mut collection2 = DeltaDataCollection::new();
    let undo_modify1 = collection2
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    let undo_modify2 = collection3
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('b'), Box::new('c'))))
        .unwrap()
        .unwrap();

    let _ = collection2.merge_delta_data(collection3).unwrap();
    collection2.undo_merge_delta_data_element(1, undo_modify2).unwrap();

    let expected_data2 = BTreeMap::from_iter(
        [(
            1,
            DeltaMapElement::DeltaUndo(DataDeltaUndo::Modify((Box::new('a'), Box::new('b')))),
        )]
        .into_iter(),
    );
    assert_eq!(collection2.data, expected_data2);

    collection2.undo_merge_delta_data_element(1, undo_modify1).unwrap();

    let _ = collection1.merge_delta_data(collection2).unwrap();

    let expected_data1 = BTreeMap::from_iter(
        [(
            1,
            DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(Box::new('a'))),
        )]
        .into_iter(),
    );
    assert_eq!(collection1.data, expected_data1);
}

#[test]
fn create_undo_modify_merge_fail() {
    let mut collection1 = DeltaDataCollection::new();
    let undo_create = collection1
        .merge_delta_data_element(1, DataDelta::Create(Box::new('a')))
        .unwrap()
        .unwrap();

    let mut collection2 = DeltaDataCollection::new();
    collection2.undo_merge_delta_data_element(1, undo_create).unwrap();

    let mut collection3 = DeltaDataCollection::new();
    let _ = collection3
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap();

    assert_eq!(
        collection2.merge_delta_data(collection3).unwrap_err(),
        Error::DeltaOverUndoApplied
    );
}

#[test]
fn create_undo_delete_merge_fail() {
    let mut collection1 = DeltaDataCollection::new();
    let undo_create = collection1
        .merge_delta_data_element(1, DataDelta::Create(Box::new('a')))
        .unwrap()
        .unwrap();

    let mut collection2 = DeltaDataCollection::new();
    collection2.undo_merge_delta_data_element(1, undo_create).unwrap();

    let mut collection3 = DeltaDataCollection::new();
    let _ = collection3
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('a')))
        .unwrap();

    assert_eq!(
        collection2.merge_delta_data(collection3).unwrap_err(),
        Error::DeltaOverUndoApplied
    );
}
