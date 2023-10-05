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

mod helpers;

struct Trivial;

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
        let app = subsystem::Manager::new("shortlived");
        let shutdown = app.make_shutdown_trigger();
        let shutdowner = tokio::spawn(async move { shutdown.initiate() });
        let _ = tokio::join!(app.main(), shutdowner);
    });
}

// Test a trivial subsystem startup/shutdown
#[test]
fn trivial() {
    let rt = helpers::init_test_runtime();
    rt.block_on(async {
        let mut app = subsystem::Manager::new("trivial");
        app.add_direct_subsystem("trivial", Trivial);
        let shutdown = app.make_shutdown_trigger();
        let shutdowner = tokio::spawn(async move { shutdown.initiate() });
        let _ = tokio::join!(app.main(), shutdowner);
    });
}

// Check subsystem panics propagate to manager
#[test]
#[should_panic]
fn panic() {
    let rt = helpers::init_test_runtime();
    rt.block_on(async {
        let mut app = subsystem::Manager::new("panic");
        let panic_subsys = app.add_direct_subsystem("panic", Trivial);
        app.add_direct_subsystem("trivial", Trivial);
        panic_subsys.as_submit_only().submit(|_| panic!("boom")).unwrap();
        app.main().await;
    });
}
