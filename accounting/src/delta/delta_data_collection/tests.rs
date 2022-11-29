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

#[test]
#[rustfmt::skip]
fn test_combine_delta_data() {
    use DataDelta::{Create, Delete, Modify};

    assert_eq!(combine_delta_data(&Create(Box::new('a')), Create(Box::new('b'))),                  Ok(DataDelta::Create(Box::new('b'))));
    assert_eq!(combine_delta_data(&Create(Box::new('a')), Modify((Box::new('a'), Box::new('b')))), Ok(DataDelta::Create(Box::new('b'))));
    assert_eq!(combine_delta_data(&Create(Box::new('a')), Delete(Box::new('a'))),                  Ok(DataDelta::Delete(Box::new('a'))));

    assert_eq!(combine_delta_data(&Modify((Box::new('a'), Box::new('b'))), Create(Box::new('c'))),                  Ok(DataDelta::Modify((Box::new('a'), Box::new('c')))));
    assert_eq!(combine_delta_data(&Modify((Box::new('a'), Box::new('b'))), Modify((Box::new('c'), Box::new('d')))), Ok(DataDelta::Modify((Box::new('a'), Box::new('d')))));
    assert_eq!(combine_delta_data(&Modify((Box::new('a'), Box::new('b'))), Delete(Box::new('c'))),                  Ok(DataDelta::Delete(Box::new('c'))));

    assert_eq!(combine_delta_data(&Delete(Box::new('a')), Create(Box::new('b'))),                  Ok(DataDelta::Create(Box::new('b'))));
    assert_eq!(combine_delta_data(&Delete(Box::new('a')), Modify((Box::new('b'), Box::new('c')))), Err(Error::DeltaDataModifyAfterDelete));
    assert_eq!(combine_delta_data(&Delete(Box::new('a')), Delete(Box::new('b'))),                  Err(Error::DeltaDataDeletedMultipleTimes));
}

#[test]
#[rustfmt::skip]
fn test_create_delta_undo() {
    use DataDelta::{Create, Delete, Modify};

    assert_eq!(create_undo_delta(Some(&Create(Box::new('a'))), Create(Box::new('b'))),                 Ok(Modify((Box::new('b'), Box::new('a')))));
    assert_eq!(create_undo_delta(Some(&Create(Box::new('a'))), Modify((Box::new('a'),Box::new('b')))), Ok(Modify((Box::new('b'), Box::new('a')))));
    assert_eq!(create_undo_delta(Some(&Create(Box::new('a'))), Delete(Box::new('a'))),                 Ok(Create(Box::new('a'))));

    assert_eq!(create_undo_delta(Some(&Modify((Box::new('a'), Box::new('b')))), Create(Box::new('c'))),                 Ok(Modify((Box::new('c'), Box::new('b')))));
    assert_eq!(create_undo_delta(Some(&Modify((Box::new('a'), Box::new('b')))), Modify((Box::new('b'),Box::new('c')))), Ok(Modify((Box::new('c'), Box::new('b')))));
    assert_eq!(create_undo_delta(Some(&Modify((Box::new('a'), Box::new('b')))), Delete(Box::new('b'))),                 Ok(Create(Box::new('b'))));

    assert_eq!(create_undo_delta(Some(&Delete(Box::new('a'))), Create(Box::new('a'))),                 Ok(Delete(Box::new('a'))));
    assert_eq!(create_undo_delta(Some(&Delete(Box::new('a'))), Modify((Box::new('a'),Box::new('b')))), Err(Error::DeltaDataModifyAfterDelete));
    assert_eq!(create_undo_delta(Some(&Delete(Box::new('a'))), Delete(Box::new('a'))),                 Err(Error::DeltaDataDeletedMultipleTimes));

    assert_eq!(create_undo_delta(None, Create(Box::new('a'))),                 Ok(Delete(Box::new('a'))));
    assert_eq!(create_undo_delta(None, Modify((Box::new('a'),Box::new('b')))), Ok(Modify((Box::new('b'), Box::new('a')))));
    assert_eq!(create_undo_delta(None, Delete(Box::new('a'))),                 Ok(Create(Box::new('a'))));
}

#[test]
fn test_merge_collections() {
    // This test check all valid combinations:
    //    collection1 - collection2
    //    -------------------------
    //         Create - Create
    //         Create - Modify
    //         Create - Delete
    //         Modify - Create
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
            (3, DataDelta::Create(Box::new('c'))),
            (4, DataDelta::Modify((Box::new('a'), Box::new('e')))),
            (5, DataDelta::Modify((Box::new('a'), Box::new('f')))),
            (6, DataDelta::Modify((Box::new('a'), Box::new('g')))),
            (7, DataDelta::Delete(Box::new('h'))),
            (8, DataDelta::Create(Box::new('i'))),
            (9, DataDelta::Modify((Box::new('a'), Box::new('j')))),
            (10, DataDelta::Delete(Box::new('k'))),
        ]
        .into_iter(),
    );

    let collection2 = DeltaDataCollection::from_iter(
        [
            (1, DataDelta::Create(Box::new('l'))),
            (2, DataDelta::Modify((Box::new('a'), Box::new('m')))),
            (3, DataDelta::Delete(Box::new('c'))),
            (4, DataDelta::Create(Box::new('o'))),
            (5, DataDelta::Modify((Box::new('c'), Box::new('p')))),
            (6, DataDelta::Delete(Box::new('g'))),
            (7, DataDelta::Create(Box::new('h'))),
            (11, DataDelta::Create(Box::new('s'))),
            (12, DataDelta::Modify((Box::new('a'), Box::new('t')))),
            (13, DataDelta::Delete(Box::new('u'))),
        ]
        .into_iter(),
    );

    let expected_data_after_merge = BTreeMap::from_iter(
        [
            (1, DeltaMapElement::Delta(DataDelta::Create(Box::new('l')))),
            (2, DeltaMapElement::Delta(DataDelta::Create(Box::new('m')))),
            (3, DeltaMapElement::Delta(DataDelta::Delete(Box::new('c')))),
            (
                4,
                DeltaMapElement::Delta(DataDelta::Modify((Box::new('a'), Box::new('o')))),
            ),
            (
                5,
                DeltaMapElement::Delta(DataDelta::Modify((Box::new('a'), Box::new('p')))),
            ),
            (6, DeltaMapElement::Delta(DataDelta::Delete(Box::new('g')))),
            (7, DeltaMapElement::Delta(DataDelta::Create(Box::new('h')))),
            (8, DeltaMapElement::Delta(DataDelta::Create(Box::new('i')))),
            (
                9,
                DeltaMapElement::Delta(DataDelta::Modify((Box::new('a'), Box::new('j')))),
            ),
            (10, DeltaMapElement::Delta(DataDelta::Delete(Box::new('k')))),
            (11, DeltaMapElement::Delta(DataDelta::Create(Box::new('s')))),
            (
                12,
                DeltaMapElement::Delta(DataDelta::Modify((Box::new('a'), Box::new('t')))),
            ),
            (13, DeltaMapElement::Delta(DataDelta::Delete(Box::new('u')))),
        ]
        .into_iter(),
    );

    let undo_data = collection1.merge_delta_data(collection2).unwrap();
    assert_eq!(collection1.data, expected_data_after_merge);

    let expected_data_after_undo = BTreeMap::from_iter(
        [
            (1, DeltaMapElement::Delta(DataDelta::Create(Box::new('a')))),
            (2, DeltaMapElement::Delta(DataDelta::Create(Box::new('b')))),
            (3, DeltaMapElement::Delta(DataDelta::Create(Box::new('c')))),
            (
                4,
                DeltaMapElement::Delta(DataDelta::Modify((Box::new('a'), Box::new('e')))),
            ),
            (
                5,
                DeltaMapElement::Delta(DataDelta::Modify((Box::new('a'), Box::new('f')))),
            ),
            (6, DeltaMapElement::Delta(DataDelta::Create(Box::new('g')))),
            (7, DeltaMapElement::Delta(DataDelta::Delete(Box::new('h')))),
            (8, DeltaMapElement::Delta(DataDelta::Create(Box::new('i')))),
            (
                9,
                DeltaMapElement::Delta(DataDelta::Modify((Box::new('a'), Box::new('j')))),
            ),
            (10, DeltaMapElement::Delta(DataDelta::Delete(Box::new('k')))),
            (11, DeltaMapElement::Delta(DataDelta::Delete(Box::new('s')))),
            (
                12,
                DeltaMapElement::Delta(DataDelta::Modify((Box::new('a'), Box::new('a')))),
            ),
            (13, DeltaMapElement::Delta(DataDelta::Create(Box::new('u')))),
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
            .undo_merge_delta_data_element(0, DataDeltaUndo(DataDelta::Create(Box::new('a'))))
            .unwrap();
        let expected_data = BTreeMap::from_iter(
            [(0, DeltaMapElement::Undo(DataDelta::Create(Box::new('a'))))].into_iter(),
        );
        assert_eq!(collection.data, expected_data);
    }

    {
        let mut collection: DeltaDataCollection<i32, char> = DeltaDataCollection::new();
        collection
            .undo_merge_delta_data_element(
                0,
                DataDeltaUndo(DataDelta::Modify((Box::new('a'), (Box::new('b'))))),
            )
            .unwrap();
        let expected_data = BTreeMap::from_iter(
            [(
                0,
                DeltaMapElement::Undo(DataDelta::Modify((Box::new('a'), Box::new('b')))),
            )]
            .into_iter(),
        );
        assert_eq!(collection.data, expected_data);
    }

    {
        let mut collection: DeltaDataCollection<i32, char> = DeltaDataCollection::new();
        collection
            .undo_merge_delta_data_element(0, DataDeltaUndo(DataDelta::Delete(Box::new('a'))))
            .unwrap();
        let expected_data = BTreeMap::from_iter(
            [(0, DeltaMapElement::Undo(DataDelta::Delete(Box::new('a'))))].into_iter(),
        );
        assert_eq!(collection.data, expected_data);
    }
}

#[test]
fn create_delete_undo_merge() {
    let mut collection1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());
    let collection1_origin = collection1.clone();

    let mut collection2 = DeltaDataCollection::new();
    let undo_op = collection2
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('a')))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_op).unwrap();

    let _ = collection2.merge_delta_data(collection3).unwrap();
    let _ = collection1.merge_delta_data(collection2).unwrap();
    assert_eq!(collection1.data, collection1_origin.data);
}

#[test]
fn create_delete_merge_undo() {
    let mut collection1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());
    let collection1_origin = collection1.clone();

    let mut collection2 = DeltaDataCollection::new();
    let undo_op = collection2
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('a')))
        .unwrap()
        .unwrap();
    let _ = collection1.merge_delta_data(collection2).unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_op).unwrap();

    let _ = collection1.merge_delta_data(collection3).unwrap();
    assert_eq!(collection1.data, collection1_origin.data);
}

#[test]
fn create_modify_undo_merge() {
    let mut collection1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());
    let collection1_origin = collection1.clone();

    let mut collection2 = DeltaDataCollection::new();
    let undo_op = collection2
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_op).unwrap();

    let _ = collection2.merge_delta_data(collection3).unwrap();
    let _ = collection1.merge_delta_data(collection2).unwrap();
    assert_eq!(collection1.data, collection1_origin.data);
}

#[test]
fn create_modify_merge_undo() {
    let mut collection1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());
    let collection1_origin = collection1.clone();

    let mut collection2 = DeltaDataCollection::new();
    let undo_op = collection2
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    let _ = collection1.merge_delta_data(collection2).unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_op).unwrap();

    let _ = collection1.merge_delta_data(collection3).unwrap();
    assert_eq!(collection1.data, collection1_origin.data);
}

#[test]
fn create_modify_merge_undo2() {
    let mut collection1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());
    let collection1_origin = collection1.clone();

    let collection2 = DeltaDataCollection::from_iter(
        [(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))].into_iter(),
    );

    let undo = collection1.merge_delta_data(collection2).unwrap();

    collection1.undo_merge_delta_data(undo).unwrap();

    assert_eq!(collection1.data, collection1_origin.data);
}

#[test]
fn create_modify_undo_undo() {
    let mut collection1 = DeltaDataCollection::new();
    let undo_op_1 = collection1
        .merge_delta_data_element(1, DataDelta::Create(Box::new('a')))
        .unwrap()
        .unwrap();

    let mut collection2 = DeltaDataCollection::new();
    let undo_op_2 = collection2
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_op_2).unwrap();

    let mut collection4 = DeltaDataCollection::new();
    collection4.undo_merge_delta_data_element(1, undo_op_1).unwrap();

    assert_eq!(
        collection3.merge_delta_data(collection4).unwrap_err(),
        Error::UndoUndoNotSupported
    );
}

#[test]
fn create_undo_modify() {
    let mut collection1 = DeltaDataCollection::new();
    let undo_op_1 = collection1
        .merge_delta_data_element(1, DataDelta::Create(Box::new('a')))
        .unwrap()
        .unwrap();

    let mut collection2 = DeltaDataCollection::new();
    collection2.undo_merge_delta_data_element(1, undo_op_1).unwrap();

    let mut collection3 = DeltaDataCollection::new();
    let _ = collection3
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap();

    assert_eq!(
        collection2.merge_delta_data(collection3).unwrap_err(),
        Error::DataCombinedOverUndoNotSupported
    );
}

#[test]
fn create_modify_undo_delete_merge() {
    let mut collection1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());

    let mut collection2 = DeltaDataCollection::new();
    let undo_op = collection2
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_op).unwrap();

    let _ = collection2.merge_delta_data(collection3).unwrap();

    let mut collection4 = DeltaDataCollection::new();
    let _ = collection4
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('b')))
        .unwrap()
        .unwrap();

    let _ = collection2.merge_delta_data(collection4).unwrap();
    let _ = collection1.merge_delta_data(collection2).unwrap();

    let expected_collection =
        DeltaDataCollection::from_iter([(1, DataDelta::Delete(Box::new('b')))].into_iter());
    assert_eq!(collection1, expected_collection);
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
    let undo_op = collection3
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('b')))
        .unwrap()
        .unwrap();

    let mut collection4 = DeltaDataCollection::new();
    collection4.undo_merge_delta_data_element(1, undo_op).unwrap();

    let _ = collection3.merge_delta_data(collection4).unwrap();
    let _ = collection2.merge_delta_data(collection3).unwrap();
    let _ = collection1.merge_delta_data(collection2).unwrap();

    let expected_collection =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('b')))].into_iter());
    assert_eq!(collection1, expected_collection);
}

#[test]
fn create_delete_undo_modify_merge() {
    let mut collection1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());

    let mut collection2 = DeltaDataCollection::new();
    let undo_op = collection2
        .merge_delta_data_element(1, DataDelta::Delete(Box::new('a')))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_op).unwrap();

    let _ = collection2.merge_delta_data(collection3).unwrap();

    let mut collection4 = DeltaDataCollection::new();
    let _ = collection4
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    let _ = collection2.merge_delta_data(collection4).unwrap();
    let _ = collection1.merge_delta_data(collection2).unwrap();

    let expected_collection =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('b')))].into_iter());
    assert_eq!(collection1, expected_collection);
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
    let undo_op = collection3
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('b'), Box::new('c'))))
        .unwrap()
        .unwrap();

    let mut collection4 = DeltaDataCollection::new();
    collection4.undo_merge_delta_data_element(1, undo_op).unwrap();

    let _ = collection3.merge_delta_data(collection4).unwrap();
    let _ = collection2.merge_delta_data(collection3).unwrap();
    let _ = collection1.merge_delta_data(collection2).unwrap();

    let expected_collection =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('b')))].into_iter());
    assert_eq!(collection1, expected_collection);
}

#[test]
fn create_modify_modify_merge_undo_undo_merge() {
    let mut collection1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());

    let mut collection2 = DeltaDataCollection::new();
    let undo_op1 = collection2
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))
        .unwrap()
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    let undo_op2 = collection3
        .merge_delta_data_element(1, DataDelta::Modify((Box::new('b'), Box::new('c'))))
        .unwrap()
        .unwrap();

    let _ = collection2.merge_delta_data(collection3).unwrap();
    collection2.undo_merge_delta_data_element(1, undo_op2).unwrap();

    let expected_collection = DeltaDataCollection::from_iter(
        [(1, DataDelta::Modify((Box::new('a'), Box::new('b'))))].into_iter(),
    );
    assert_eq!(collection2, expected_collection);

    collection2.undo_merge_delta_data_element(1, undo_op1).unwrap();

    let _ = collection1.merge_delta_data(collection2).unwrap();

    let expected_collection =
        DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());
    assert_eq!(collection1, expected_collection);
}
