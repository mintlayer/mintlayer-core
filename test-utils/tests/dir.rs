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

#[test]
fn existing_dir_error() {
    pub const TARGET_TMPDIR: &str = env!("CARGO_TARGET_TMPDIR");
    // Target tmpdir should have been created by cargo, check we get the expected error code
    match std::fs::create_dir(TARGET_TMPDIR) {
        Ok(()) => panic!("expected dir creation to fail"),
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists),
    }
}
