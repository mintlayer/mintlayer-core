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

static INIT: std::sync::Once = std::sync::Once::new();

pub fn init_test_runtime() -> tokio::runtime::Runtime {
    INIT.call_once(|| logging::init_logging::<&std::path::Path>(None));

    let mut runtime = tokio::runtime::Builder::new_multi_thread();
    #[cfg(not(loom))]
    runtime.enable_all();
    runtime.worker_threads(4).build().unwrap()
}
