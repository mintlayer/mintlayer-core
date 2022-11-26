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

    assert_eq!(combine_delta_data(&Create(Box::new('a')), Create(Box::new('b'))), Err(Error::DeltaDataCreatedMultipleTimes));
    assert_eq!(combine_delta_data(&Create(Box::new('a')), Modify(Box::new('b'))), Ok(DeltaMapOp::Write(DataDelta::Create(Box::new('b')))));
    assert_eq!(combine_delta_data(&Create(Box::new('a')), Delete(Box::new('a'))), Ok(DeltaMapOp::Erase));

    assert_eq!(combine_delta_data(&Modify(Box::new('a')), Create(Box::new('b'))), Err(Error::DeltaDataCreatedMultipleTimes));
    assert_eq!(combine_delta_data(&Modify(Box::new('a')), Modify(Box::new('b'))), Ok(DeltaMapOp::Write(DataDelta::Modify(Box::new('b')))));
    assert_eq!(combine_delta_data(&Modify(Box::new('a')), Delete(Box::new('a'))), Ok(DeltaMapOp::Erase));

    assert_eq!(combine_delta_data(&Delete(Box::new('a')), Create(Box::new('b'))), Ok(DeltaMapOp::Write(DataDelta::Create(Box::new('b')))));
    assert_eq!(combine_delta_data(&Delete(Box::new('a')), Modify(Box::new('b'))), Err(Error::DeltaDataModifyAfterDelete));
    assert_eq!(combine_delta_data(&Delete(Box::new('a')), Delete(Box::new('b'))), Err(Error::DeltaDataDeletedMultipleTimes));
}

#[test]
#[rustfmt::skip]
fn test_combine_delta_elements() {
    //FIXME
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
            (3, DataDelta::Modify(Box::new('c'))),
            (4, DataDelta::Modify(Box::new('d'))),
            (5, DataDelta::Delete(Box::new('e'))),
            (6, DataDelta::Create(Box::new('f'))),
            (7, DataDelta::Modify(Box::new('g'))),
            (8, DataDelta::Delete(Box::new('h'))),
        ]
        .into_iter(),
    );
    let collection1_origin = collection1.clone();

    let collection2 = DeltaDataCollection::from_iter(
        [
            (1, DataDelta::Modify(Box::new('i'))),
            (2, DataDelta::Delete(Box::new('j'))),
            (3, DataDelta::Modify(Box::new('k'))),
            (4, DataDelta::Delete(Box::new('l'))),
            (5, DataDelta::Create(Box::new('m'))),
            (9, DataDelta::Create(Box::new('n'))),
            (10, DataDelta::Modify(Box::new('o'))),
            (11, DataDelta::Delete(Box::new('p'))),
        ]
        .into_iter(),
    );

    let expected_data = BTreeMap::from_iter(
        [
            (1, DeltaMapElement::Data(DataDelta::Create(Box::new('i')))),
            // 2 was erased
            (3, DeltaMapElement::Data(DataDelta::Modify(Box::new('k')))),
            // 4 was erased
            (5, DeltaMapElement::Data(DataDelta::Create(Box::new('m')))),
            (6, DeltaMapElement::Data(DataDelta::Create(Box::new('f')))),
            (7, DeltaMapElement::Data(DataDelta::Modify(Box::new('g')))),
            (8, DeltaMapElement::Data(DataDelta::Delete(Box::new('h')))),
            (9, DeltaMapElement::Data(DataDelta::Create(Box::new('n')))),
            (10, DeltaMapElement::Data(DataDelta::Modify(Box::new('o')))),
            (11, DeltaMapElement::Data(DataDelta::Delete(Box::new('p')))),
        ]
        .into_iter(),
    );

    let undo_data = collection1.merge_delta_data(collection2).unwrap();
    assert_eq!(collection1.data, expected_data);

    collection1.undo_merge_delta_data(undo_data).unwrap();
    assert_eq!(collection1.data, collection1_origin.data);
}

#[test]
fn test_undo_nonexisting_delta() {
    {
        let mut collection: DeltaDataCollection<i32, char> = DeltaDataCollection::new();
        collection
            .undo_merge_delta_data_element(
                0,
                DataDeltaUndoOp::new_erase(DataDelta::Create(Box::new('a'))),
            )
            .unwrap();
        let expected_data = BTreeMap::from_iter(
            [(
                0,
                DeltaMapElement::Operation(DataDeltaUndoOp::new_erase(DataDelta::Create(
                    Box::new('a'),
                ))),
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
                DataDeltaUndoOp::new_write(DataDelta::Create(Box::new('a'))),
            )
            .unwrap();
        let expected_data =
            DeltaDataCollection::from_iter([(0, DataDelta::Create(Box::new('a')))].into_iter());
        assert_eq!(collection, expected_data);
    }

    {
        let mut collection: DeltaDataCollection<i32, char> = DeltaDataCollection::new();
        collection
            .undo_merge_delta_data_element(
                0,
                DataDeltaUndoOp::new_write(DataDelta::Modify(Box::new('a'))),
            )
            .unwrap();
        let expected_data =
            DeltaDataCollection::from_iter([(0, DataDelta::Modify(Box::new('a')))].into_iter());
        assert_eq!(collection, expected_data);
    }

    {
        let mut collection: DeltaDataCollection<i32, char> = DeltaDataCollection::new();
        collection
            .undo_merge_delta_data_element(
                0,
                DataDeltaUndoOp::new_write(DataDelta::Delete(Box::new('a'))),
            )
            .unwrap();
        let expected_data =
            DeltaDataCollection::from_iter([(0, DataDelta::Delete(Box::new('a')))].into_iter());
        assert_eq!(collection, expected_data);
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
        .merge_delta_data_element(1, DataDelta::Modify(Box::new('b')))
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
        .merge_delta_data_element(1, DataDelta::Modify(Box::new('b')))
        .unwrap();

    let _ = collection1.merge_delta_data(collection2).unwrap();

    let mut collection3 = DeltaDataCollection::new();
    collection3.undo_merge_delta_data_element(1, undo_op).unwrap();

    let _ = collection1.merge_delta_data(collection3).unwrap();
    assert_eq!(collection1.data, collection1_origin.data);
}

#[test]
fn merge_undo_with_undo() {
    let mut collection2 = DeltaDataCollection::new();
    let undo_op_1 = collection2
        .merge_delta_data_element(1, DataDelta::Create(Box::new('b')))
        .unwrap();

    let mut collection3 = DeltaDataCollection::new();
    let undo_op_2 = collection3
        .merge_delta_data_element(1, DataDelta::Modify(Box::new('b')))
        .unwrap();

    let mut collection4 = DeltaDataCollection::new();
    collection4.undo_merge_delta_data_element(1, undo_op_1).unwrap();

    let mut collection5 = DeltaDataCollection::new();
    collection5.undo_merge_delta_data_element(1, undo_op_2).unwrap();

    assert_eq!(
        collection4.merge_delta_data(collection5).unwrap_err(),
        Error::UndoOpsCombinedNotSupported
    );
}

#[test]
fn merge_undo_with_data() {
    let mut collection1 = DeltaDataCollection::new();
    let undo_op_1 = collection1
        .merge_delta_data_element(1, DataDelta::Create(Box::new('b')))
        .unwrap();

    let mut collection2 = DeltaDataCollection::new();
    collection2.undo_merge_delta_data_element(1, undo_op_1).unwrap();

    let mut collection3 = DeltaDataCollection::new();
    let _ = collection3
        .merge_delta_data_element(1, DataDelta::Modify(Box::new('c')))
        .unwrap();

    assert_eq!(
        collection2.merge_delta_data(collection3).unwrap_err(),
        Error::DataCombinedOverUndoOpNotSupported
    );
}
