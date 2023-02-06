// Copyright (c) 2022 RBB S.r.l
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

use std::{collections::BTreeMap, sync::Mutex};

use memsize::MemSize;
use rstest::rstest;
use storage_core::{
    backend::{ReadOps, TxRw, WriteOps},
    Backend,
};
use tempdir::TempDir;
use test_utils::random::make_seedable_rng;
use test_utils::random::{CryptoRng, Rng, Seed};

use super::*;

#[must_use]
fn create_random_data_map_with_target_byte_size(
    rng: &mut (impl Rng + CryptoRng),
    required_size: usize,
    key_max_size: usize,
    val_max_size: usize,
) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let mut result = BTreeMap::new();

    let mut total_size = 0;

    while total_size < required_size {
        let key_size = 1 + rng.gen::<usize>() % key_max_size;
        let key = (0..key_size).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();
        let val_size = 1 + rng.gen::<usize>() % val_max_size;
        let val = (0..val_size).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();
        result.insert(key, val);

        total_size += key_size;
        total_size += val_size;
    }

    result
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
fn auto_map_resize_between_txs(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let resize_actions = Arc::new(Mutex::new(Vec::new()));

        let resize_actions_for_check = Arc::clone(&resize_actions);
        let resize_actions = Arc::clone(&resize_actions);
        let resize_callback = Box::new(move |v| resize_actions.lock().unwrap().push(v));

        let initial_map_size = 1 << 20;

        let resize_settings = DatabaseResizeSettings {
            min_resize_step: 1 << 16,
            max_resize_step: 1 << 20,
            default_resize_ratio_percentage: 10,
            resize_trigger_percentage: 0.9,
        };

        let data_dir = TempDir::new("lmdb_resize").unwrap();
        let lmdb = Lmdb::new(
            data_dir.into_path(),
            MemSize::from_bytes(initial_map_size).into(),
            resize_settings.clone(),
            MapResizeCallback::new(resize_callback),
        );

        let lmdb_impl = lmdb.open(DbDesc::from_iter(vec![MapDesc::new("SomeDb")])).unwrap();

        // generate random values with a predefined target size that surpasses the current map size
        let data = create_random_data_map_with_target_byte_size(
            &mut rng,
            (initial_map_size * 5) as usize,
            500,
            10000,
        );

        let mut resizes_via_commit_count = 0usize;

        // write many key/val values, and while they're being written, expect that database map will grow
        for (key, val) in &data {
            let mut rw_tx = lmdb_impl.transaction_rw(None).unwrap();
            rw_tx.put(DbIndex::new(0), key.clone(), val.clone()).unwrap();
            match rw_tx.commit() {
                Ok(_) => resizes_via_commit_count += 1,
                Err(e) => panic!("Failed to commit: {e:?}"),
            }
        }

        let resize_action_result = resize_actions_for_check.lock().unwrap().clone();
        assert!(!resize_action_result.is_empty());
        for act in resize_action_result {
            assert!(act.old_size < act.new_size);
            assert!(act.new_size - act.old_size >= resize_settings.min_resize_step as u64);
            assert!(act.new_size - act.old_size <= resize_settings.max_resize_step as u64);
        }

        // ensure data is successfully written
        let ro_tx = lmdb_impl.transaction_ro().unwrap();
        for (key, val) in data {
            assert_eq!(ro_tx.get(DbIndex::new(0), &key).unwrap().unwrap(), val);
        }

        assert!(resizes_via_commit_count > 0, "Not a single resize was scheduled after a transaction... this is very unlikely based on the test structure");
    })
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
fn auto_map_resize_between_puts(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let resize_actions = Arc::new(Mutex::new(Vec::new()));

        let resize_actions_for_check = Arc::clone(&resize_actions);
        let resize_actions = Arc::clone(&resize_actions);
        let resize_callback = Box::new(move |v| resize_actions.lock().unwrap().push(v));

        let initial_map_size = 1 << 20;

        let resize_settings = DatabaseResizeSettings {
            min_resize_step: 1 << 16,
            max_resize_step: 1 << 20,
            default_resize_ratio_percentage: 10,
            resize_trigger_percentage: 0.9,
        };

        let data_dir = TempDir::new("lmdb_resize").unwrap();
        let lmdb = Lmdb::new(
            data_dir.into_path(),
            MemSize::from_bytes(initial_map_size).into(),
            resize_settings.clone(),
            MapResizeCallback::new(resize_callback),
        );

        let lmdb_impl = lmdb.open(DbDesc::from_iter(vec![MapDesc::new("SomeDb")])).unwrap();

        // generate random values with a predefined target size that surpasses the current map size
        let data = create_random_data_map_with_target_byte_size(
            &mut rng,
            (initial_map_size * 5) as usize,
            500,
            10000,
        );

        // write many key/val values, and while they're being written, expect that database map will grow
        // In this loop, we expect two things to schedule a resize:
        // 1. While putting in the transaction
        // 2. While committing a transaction
        // We focus on while writing in the transaction
        ////////////////////////////////////////////////
        // Data stack is the full data that should be written to the database in a stack that we pop
        let mut data_stack: Vec<(Vec<u8>, Vec<u8>)> = data.clone().into_iter().collect();
        let mut resizes_via_put_count = 0usize;
        'outer: loop {
            let mut rw_tx = lmdb_impl.transaction_rw(None).unwrap();
            let mut data_written_in_this_cycle = Vec::new();
            while !data_stack.is_empty() {
                let (key, val) = data_stack.last().unwrap();
                match rw_tx.put(DbIndex::new(0), key.clone(), val.clone()) {
                    Ok(_) => {
                        // on success, we continue writing and take record of that
                        data_written_in_this_cycle.push(data_stack.pop().unwrap());
                    }
                    Err(_) => {
                        // on failure, we expect a resize to happen after trying again, so we consider this cycle a failure and restore what we (unsuccessfully) wrote to the stack
                        data_stack.extend(data_written_in_this_cycle);
                        resizes_via_put_count += 1;
                        continue 'outer;
                    }
                }
            }
            match rw_tx.commit() {
                Ok(_) => break,
                Err(_) => {
                    // on error, we continue, but return the data that failed writing to the stack
                    data_stack.extend(data_written_in_this_cycle);
                    continue 'outer;
                }
            }
        }
        let resize_action_result = resize_actions_for_check.lock().unwrap().clone();
        assert!(!resize_action_result.is_empty());
        for act in resize_action_result {
            assert!(act.old_size < act.new_size);
            assert!(act.new_size - act.old_size >= resize_settings.min_resize_step as u64);
            assert!(act.new_size - act.old_size <= resize_settings.max_resize_step as u64);
        }

        // ensure data is successfully written
        let ro_tx = lmdb_impl.transaction_ro().unwrap();
        for (key, val) in data {
            assert_eq!(ro_tx.get(DbIndex::new(0), &key).unwrap().unwrap(), val);
        }

        assert!(
        resizes_via_put_count > 0,
        "Not a single resize was scheduled after a write/put... this is very unlikely based on the test structure"
    );
    })
}
