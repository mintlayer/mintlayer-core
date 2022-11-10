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

use storage_core::{backend, info::MapDesc, Backend, DbDesc, DbIndex};
use storage_lmdb::{Lmdb, MemSize};
use utils::{concurrency, thread};

const IDX0: DbIndex = DbIndex::new(0);

fn perform_writes(
    name: &'static str,
    initial_size: MemSize,
    tx_size: MemSize,
    write_sizes: &[MemSize],
) {
    #[cfg(not(loom))]
    logging::init_logging::<&std::path::Path>(None);
    let test_root = std::sync::Arc::new(test_utils::test_root!("remap-tests").unwrap());

    concurrency::model({
        let test_root = std::sync::Arc::clone(&test_root);
        let write_sizes = write_sizes.to_vec();
        move || {
            // Open a new datbase with given map size
            let dir = test_root.fresh_test_dir(name).as_ref().to_owned();
            let lmdb = Lmdb::new(dir)
                .with_map_size(initial_size)
                .with_tx_size(tx_size)
                .open(DbDesc::from_iter(std::iter::once(MapDesc::new("map"))))
                .unwrap();

            // Try inserting values with sizes given by the `write_sizes` param
            for (i, size) in write_sizes.iter().enumerate() {
                let mut txrw = backend::TransactionalRw::transaction_rw(&lmdb).unwrap();
                let val = vec![42u8; size.as_bytes()];
                backend::WriteOps::put(&mut txrw, IDX0, i.to_le_bytes().to_vec(), val).unwrap();
                backend::TxRw::commit(txrw).unwrap();
            }
        }
    });

    std::sync::Arc::try_unwrap(test_root).unwrap().delete();
}

#[test]
fn map_too_small_initially() {
    perform_writes(
        "map_too_small_initially",
        MemSize::from_kilobytes(100),
        MemSize::from_kilobytes(300),
        [MemSize::from_kilobytes(111)].as_ref(),
    );
}

#[test]
fn map_too_small_by_a_lot() {
    perform_writes(
        "map_too_small_by_a_lot",
        MemSize::from_kilobytes(200),
        MemSize::from_megabytes(55),
        [MemSize::from_megabytes(50)].as_ref(),
    );
}

#[test]
fn map_too_small_after_a_number_of_writes() {
    let write_sizes = [MemSize::from_kilobytes(100); 100];
    perform_writes(
        "map_too_small_after_a_number_of_writes",
        MemSize::from_kilobytes(400),
        MemSize::from_kilobytes(200),
        write_sizes.as_ref(),
    );
}

#[test]
#[should_panic]
fn tx_size_too_small() {
    perform_writes(
        "tx_size_too_small",
        MemSize::from_kilobytes(200),
        MemSize::from_megabytes(20),
        [MemSize::from_megabytes(50)].as_ref(),
    );
}

#[test]
fn two_concurrent_writers() {
    #[cfg(not(loom))]
    logging::init_logging::<&std::path::Path>(None);
    let test_root = std::sync::Arc::new(test_utils::test_root!("remap-tests").unwrap());

    concurrency::model({
        let test_root = std::sync::Arc::clone(&test_root);
        move || {
            // Open a new datbase with initial map size 500kB, with 500kB transactions
            let dir = test_root.fresh_test_dir("two_concurrent_writes").as_ref().to_owned();
            let storage = Lmdb::new(dir)
                .with_map_size(MemSize::from_kilobytes(500))
                .with_tx_size(MemSize::from_kilobytes(500))
                .open(DbDesc::from_iter(std::iter::once(MapDesc::new("map"))))
                .unwrap();

            let spawn_writer = |key: Vec<u8>| {
                let storage = storage.clone();
                thread::spawn(move || {
                    let mut txrw = backend::TransactionalRw::transaction_rw(&storage).unwrap();
                    let val = vec![0x33u8; MemSize::from_kilobytes(300).as_bytes()];
                    backend::WriteOps::put(&mut txrw, IDX0, key, val).unwrap();
                    backend::TxRw::commit(txrw).unwrap();
                })
            };

            let wr0 = spawn_writer(b"wr0".to_vec());
            let wr1 = spawn_writer(b"wr1".to_vec());

            wr0.join().unwrap();
            wr1.join().unwrap();
        }
    });

    std::sync::Arc::try_unwrap(test_root).unwrap().delete();
}
