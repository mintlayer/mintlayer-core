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

// None + Create('a') + Undo(Create('a')) = None
#[test]
fn none_create_undo() {
    let mut collection_with_delta = DeltaDataCollection::new();
    let undo_create = collection_with_delta
        .merge_delta_data_element(1, DataDelta::Create('a'))
        .unwrap()
        .unwrap();

    let mut collection_with_undo = DeltaDataCollection::new();
    collection_with_undo.undo_merge_delta_data_element(1, undo_create).unwrap();

    let result = combine_data_with_delta(
        None,
        Some(collection_with_delta.data().iter().next().unwrap().1),
    )
    .unwrap();
    assert_eq!(result, Some('a'));

    let result = combine_data_with_delta(
        result.as_ref(),
        Some(collection_with_undo.data().iter().next().unwrap().1),
    )
    .unwrap();
    assert_eq!(result, None);
}

// Some('a') + Delete('a') + Undo(Delete('a')) = Some('a')
#[test]
fn some_delete_undo() {
    let initial_data = 'a';

    let mut collection_with_delta = DeltaDataCollection::new();
    let undo_delete = collection_with_delta
        .merge_delta_data_element(1, DataDelta::Delete('a'))
        .unwrap()
        .unwrap();

    let mut collection_with_undo = DeltaDataCollection::new();
    collection_with_undo.undo_merge_delta_data_element(1, undo_delete).unwrap();

    let result = combine_data_with_delta(
        Some(&initial_data),
        Some(collection_with_delta.data().iter().next().unwrap().1),
    )
    .unwrap();
    assert_eq!(result, None);

    let result = combine_data_with_delta(
        result.as_ref(),
        Some(collection_with_undo.data().iter().next().unwrap().1),
    )
    .unwrap();
    assert_eq!(result, Some('a'));
}

// Some('a') + Modify'a', 'b' + Undo(Modify('b', 'a')) = Some('a')
#[test]
fn some_modify_undo() {
    let initial_data = 'a';

    let mut collection_with_modify = DeltaDataCollection::new();
    let undo_modify = collection_with_modify
        .merge_delta_data_element(1, DataDelta::Modify('a', 'b'))
        .unwrap()
        .unwrap();

    let mut collection_with_undo = DeltaDataCollection::new();
    collection_with_undo.undo_merge_delta_data_element(1, undo_modify).unwrap();

    let result = combine_data_with_delta(
        Some(&initial_data),
        Some(collection_with_modify.data().iter().next().unwrap().1),
    )
    .unwrap();
    assert_eq!(result, Some('b'));

    let result = combine_data_with_delta(
        result.as_ref(),
        Some(collection_with_undo.data().iter().next().unwrap().1),
    )
    .unwrap();
    assert_eq!(result, Some('a'));
}

#[test]
fn none_create_delete() {
    let collection_with_create =
        DeltaDataCollection::from_iter([(1, DataDelta::Create('a'))].into_iter());

    let collection_with_delete =
        DeltaDataCollection::from_iter([(1, DataDelta::Delete('a'))].into_iter());

    // None + Create('a') + Delete('a')  = None
    {
        let result = combine_data_with_delta(
            None,
            Some(collection_with_create.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, Some('a'));

        let result = combine_data_with_delta(
            result.as_ref(),
            Some(collection_with_delete.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, None);
    }

    // None + (Create('a') + Delete('a'))  = None
    {
        let mut collection_with_create = collection_with_create;
        let _ = collection_with_create.merge_delta_data(collection_with_delete).unwrap();
        assert!(collection_with_create.data().is_empty());

        let result: Option<char> = combine_data_with_delta(None, None).unwrap();
        assert_eq!(result, None);
    }
}

#[test]
fn none_create_modify_delete() {
    let collection_with_create =
        DeltaDataCollection::from_iter([(1, DataDelta::Create('a'))].into_iter());

    let collection_with_modify =
        DeltaDataCollection::from_iter([(1, DataDelta::Modify('a', 'b'))].into_iter());

    let collection_with_delete =
        DeltaDataCollection::from_iter([(1, DataDelta::Delete('b'))].into_iter());

    // None + Create('a') + Modify'a', 'b' + Delete('a')  = None
    {
        let result = combine_data_with_delta(
            None,
            Some(collection_with_create.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, Some('a'));

        let result = combine_data_with_delta(
            result.as_ref(),
            Some(collection_with_modify.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, Some('b'));

        let result = combine_data_with_delta(
            result.as_ref(),
            Some(collection_with_delete.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, None);
    }

    // None + (Create('a') + Modify'a', 'b' + Delete('a'))  = None
    {
        let mut collection_with_create = collection_with_create.clone();
        let _ = collection_with_create.merge_delta_data(collection_with_modify.clone()).unwrap();
        let _ = collection_with_create.merge_delta_data(collection_with_delete.clone()).unwrap();
        assert!(collection_with_create.data().is_empty());

        let result: Option<char> = combine_data_with_delta(None, None).unwrap();
        assert_eq!(result, None);
    }

    // None + (Create('a') + (Modify'a', 'b' + Delete('a')))  = None
    {
        let mut collection_with_create = collection_with_create;
        let mut collection_with_modify = collection_with_modify;
        let _ = collection_with_modify.merge_delta_data(collection_with_delete).unwrap();
        let _ = collection_with_create.merge_delta_data(collection_with_modify).unwrap();
        assert!(collection_with_create.data().is_empty());

        let result: Option<char> = combine_data_with_delta(None, None).unwrap();
        assert_eq!(result, None);
    }
}

#[test]
fn some_delete_create() {
    let initial_data = 'a';

    let collection_with_delete =
        DeltaDataCollection::from_iter([(1, DataDelta::Delete('a'))].into_iter());

    let collection_with_create =
        DeltaDataCollection::from_iter([(1, DataDelta::Create('b'))].into_iter());

    // Some('a') + Delete('a') + Create('b') = 'b'
    {
        let result = combine_data_with_delta(
            Some(&initial_data),
            Some(collection_with_delete.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, None);

        let result = combine_data_with_delta(
            result.as_ref(),
            Some(collection_with_create.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, Some('b'));
    }

    // Some('a') + (Delete('a') + Create('b')) = 'b'
    {
        let mut collection_with_delete = collection_with_delete;
        let _ = collection_with_delete.merge_delta_data(collection_with_create).unwrap();

        let result = combine_data_with_delta(
            Some(&initial_data),
            Some(collection_with_delete.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, Some('b'));
    }
}

#[test]
fn none_create_modify_undo() {
    let collection_with_create =
        DeltaDataCollection::from_iter([(1, DataDelta::Create('a'))].into_iter());

    let mut collection_with_modify = DeltaDataCollection::new();
    let undo_modify = collection_with_modify
        .merge_delta_data_element(1, DataDelta::Modify('a', 'b'))
        .unwrap()
        .unwrap();

    let mut collection_with_undo = DeltaDataCollection::new();
    collection_with_undo.undo_merge_delta_data_element(1, undo_modify).unwrap();

    // None + Create('a') + Modify'a', 'b' + Undo(Modify('b','a')) = 'a'
    {
        let result = combine_data_with_delta(
            None,
            Some(collection_with_create.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, Some('a'));

        let result = combine_data_with_delta(
            result.as_ref(),
            Some(collection_with_modify.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, Some('b'));

        let result = combine_data_with_delta(
            result.as_ref(),
            Some(collection_with_undo.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, Some('a'));
    }

    // None + ((Create('a') + Modify'a', 'b') + Undo(Modify('b','a'))) = 'a'
    {
        let mut collection_with_create = collection_with_create;
        let _ = collection_with_create.merge_delta_data(collection_with_modify).unwrap();
        let _ = collection_with_create.merge_delta_data(collection_with_undo).unwrap();

        let result = combine_data_with_delta(
            None,
            Some(collection_with_create.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, Some('a'));
    }
}

#[test]
fn some_modify_delete_undo() {
    let initial_data = 'a';

    let collection_with_modify =
        DeltaDataCollection::from_iter([(1, DataDelta::Modify('a', 'b'))].into_iter());

    let mut collection_with_delete = DeltaDataCollection::new();
    let undo_delete = collection_with_delete
        .merge_delta_data_element(1, DataDelta::Delete('b'))
        .unwrap()
        .unwrap();

    let mut collection_with_undo = DeltaDataCollection::new();
    collection_with_undo.undo_merge_delta_data_element(1, undo_delete).unwrap();

    // Some('a') + Modify'a', 'b' + Delete('b') + Undo(Delete('b')) = 'b'
    {
        let result = combine_data_with_delta(
            Some(&initial_data),
            Some(collection_with_modify.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, Some('b'));

        let result = combine_data_with_delta(
            result.as_ref(),
            Some(collection_with_delete.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, None);

        let result = combine_data_with_delta(
            result.as_ref(),
            Some(collection_with_undo.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, Some('b'));
    }

    // Some('a') + ((Modify'a', 'b' + Delete('b')) + Undo(Delete('b'))) = 'b'
    {
        let mut collection_with_modify = collection_with_modify;
        let _ = collection_with_modify.merge_delta_data(collection_with_delete).unwrap();
        let _ = collection_with_modify.merge_delta_data(collection_with_undo).unwrap();

        let result = combine_data_with_delta(
            Some(&initial_data),
            Some(collection_with_modify.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, Some('b'));
    }
}

#[test]
fn some_modify_modify_undo() {
    let initial_data = 'a';

    let collection_with_modify1 =
        DeltaDataCollection::from_iter([(1, DataDelta::Modify('a', 'b'))].into_iter());

    let mut collection_with_modify2 = DeltaDataCollection::new();
    let undo_delete = collection_with_modify2
        .merge_delta_data_element(1, DataDelta::Modify('b', 'c'))
        .unwrap()
        .unwrap();

    let mut collection_with_undo = DeltaDataCollection::new();
    collection_with_undo.undo_merge_delta_data_element(1, undo_delete).unwrap();

    // Some('a') + Modify'a', 'b' + Modify('b', 'c') + Undo(Modify('c', 'b')) = 'b'
    {
        let result = combine_data_with_delta(
            Some(&initial_data),
            Some(collection_with_modify1.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, Some('b'));

        let result = combine_data_with_delta(
            result.as_ref(),
            Some(collection_with_modify2.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, Some('c'));

        let result = combine_data_with_delta(
            result.as_ref(),
            Some(collection_with_undo.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, Some('b'));
    }

    // Some('a') + ((Modify'a', 'b' + Modify('b', 'c')) + Undo(Modify('c', 'b'))) = 'b'
    {
        let mut collection_with_modify = collection_with_modify1;
        let _ = collection_with_modify.merge_delta_data(collection_with_modify2).unwrap();
        let _ = collection_with_modify.merge_delta_data(collection_with_undo).unwrap();

        let result = combine_data_with_delta(
            Some(&initial_data),
            Some(collection_with_modify.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, Some('b'));
    }
}

#[test]
fn some_delete_create_undo() {
    let initial_data = 'a';

    let collection_with_delete =
        DeltaDataCollection::from_iter([(1, DataDelta::Delete('a'))].into_iter());

    let mut collection_with_create = DeltaDataCollection::new();
    let undo_create = collection_with_create
        .merge_delta_data_element(1, DataDelta::Create('b'))
        .unwrap()
        .unwrap();

    let mut collection_with_undo = DeltaDataCollection::new();
    collection_with_undo.undo_merge_delta_data_element(1, undo_create).unwrap();

    // Some('a') + Delete('a') + Create('b') + Undo(Create('b')) = None
    {
        let result = combine_data_with_delta(
            Some(&initial_data),
            Some(collection_with_delete.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, None);

        let result = combine_data_with_delta(
            result.as_ref(),
            Some(collection_with_create.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, Some('b'));

        let result = combine_data_with_delta(
            result.as_ref(),
            Some(collection_with_undo.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, None);
    }

    // Some('a') + ((Delete('a') + Create('b')) + Undo(Create('b'))) = None
    {
        let mut collection_with_modify = collection_with_delete;
        let _ = collection_with_modify.merge_delta_data(collection_with_create).unwrap();
        let _ = collection_with_modify.merge_delta_data(collection_with_undo).unwrap();

        let result = combine_data_with_delta(
            Some(&initial_data),
            Some(collection_with_modify.data().iter().next().unwrap().1),
        )
        .unwrap();
        assert_eq!(result, None);
    }
}
