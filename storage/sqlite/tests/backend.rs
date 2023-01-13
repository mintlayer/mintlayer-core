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

use storage_lmdb::Lmdb;

fn main() {
    let test_root = test_utils::test_root!("backend-tests").unwrap();

    // Backend creation procedure
    let create_backend = {
        let test_root = test_root.clone();
        move || {
            // Each test case gets its own subdirectory to avoid clashes
            let test_dir = test_root.fresh_test_dir("unknown");
            Lmdb::new(test_dir.as_ref().to_path_buf())
        }
    };

    // Now run the tests
    let result = storage_backend_test_suite::main(create_backend);

    // Remove the test directory unless there was a failure.
    // In case of failure, it is kept to give us the opportunity to inspect database contents.
    if !result.has_failed() {
        test_root.delete();
    }

    result.exit()
}
