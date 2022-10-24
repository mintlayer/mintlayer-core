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

use std::{fs, path::PathBuf, sync::atomic::AtomicU32};

use storage_lmdb::Lmdb;

const TARGET_TMPDIR: &str = env!("CARGO_TARGET_TMPDIR");

fn main() {
    // Initialize the directory for database files used by tests
    let test_dir = {
        // Put database files under $CARGO_TARGET_TMPDIR/lmdb_backend_tests/run_$RANDOM_U32_HEX
        let mut dir = PathBuf::from(TARGET_TMPDIR);
        dir.push("lmdb_backend_tests");
        dir.push(format!("run_{:08x}", rand::random::<u32>()));
        fs::create_dir_all(dir.as_path()).expect("test run dir creation to succeed");
        dir
    };

    // Backend creation procedure
    let counter = AtomicU32::new(0);
    let create_backend = {
        let test_dir = test_dir.clone();
        move || {
            // Each test case gets its own subdirectory to avid clashes
            let seq_no = counter.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let test_dir = test_dir.join(format!("case_{:08x}", seq_no));
            Lmdb::new(test_dir)
        }
    };

    // Now run the tests
    let result = storage_backend_test_suite::main(create_backend);

    // Remove the test directory unless there was a failure.
    // In case of failure, it is kept to give us the opportunity to inspect database contents.
    if !result.has_failed() {
        fs::remove_dir_all(test_dir).expect("test run dir deletion to succeed");
    }

    result.exit()
}
