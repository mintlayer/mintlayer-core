// Copyright (c) 2021-2024 RBB S.r.l
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

use std::path::{PathBuf, MAIN_SEPARATOR};

fn main() {
    let manifest_dir =
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is missing or invalid");
    // Note: there is no point in allowing non-utf-8 strings here, because we won't be able
    // to propagate them further anyway.
    // Also note that if we tried accessing CARGO_MANIFEST_DIR directly from the code via env!
    // and it wasn't Unicode, the compilation would fail anyway, complaining that the env var
    // is not defined.
    let manifest_dir = manifest_dir.to_str().expect("CARGO_MANIFEST_DIR is not a Unicode string");

    let ws_root_dir = {
        let mut path_buf = PathBuf::new();
        path_buf.push(manifest_dir);
        path_buf.pop();
        path_buf
    };

    println!(
        "cargo:rustc-env=WORKSPACE_PATH={}{}",
        ws_root_dir.to_str().expect("ws_root_dir must be Unicode"),
        MAIN_SEPARATOR
    );
}
