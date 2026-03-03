// Copyright (c) 2023 RBB S.r.l
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

use node_lib::run_node_daemon;

#[tokio::main]
async fn main() {
    utils::rust_backtrace::enable();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    let exit_code = run_node_daemon().await.unwrap_or_else(|err| {
        eprintln!("Mintlayer node launch failed: {err:?}");
        std::process::exit(1)
    });

    std::process::exit(exit_code.0)
}
