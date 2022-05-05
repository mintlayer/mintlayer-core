// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): L. Kuklinek

use subsystem::subsystem::CallRequest;

mod helpers;

struct Trivial;
impl subsystem::Subsystem for Trivial {}

// Test an empty app startup/shutdown
#[test]
fn empty() {
    let rt = helpers::init_test_runtime();
    rt.block_on(async {
        let app = subsystem::Manager::new("empty");
        app.main().await;
    });
}

// Test a startup/shutdown with a single subsystem that immediately exits
#[test]
fn shortlived() {
    let rt = helpers::init_test_runtime();
    rt.block_on(async {
        let mut app = subsystem::Manager::new("shortlived");
        app.start_raw("nop", |_: CallRequest<()>, _| async {});
        app.main().await;
    });
}

// Test a trivial subsystem sartup/shutdown
#[test]
fn trivial() {
    let rt = helpers::init_test_runtime();
    rt.block_on(async {
        let mut app = subsystem::Manager::new("trivial");
        app.start("trivial", Trivial);
        app.start_raw("nop", |_: CallRequest<()>, _| async {});
        app.main().await;
    });
}
