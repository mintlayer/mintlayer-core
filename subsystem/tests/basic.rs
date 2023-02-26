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

mod helpers;
mod sample_subsystems;

use sample_subsystems::{Counter, Substringer};

#[test]
fn basic_passive_shutdown() {
    let runtime = helpers::init_test_runtime();
    utils::concurrency::model(move || {
        runtime.block_on(async {
            let mut app = subsystem::Manager::new("app");

            let _substr = app.add_subsystem("substr", Substringer::new("abc".into()));
            let _counter = app.add_subsystem("counter", Counter::new());

            // Start a subsystem that immediately terminates, instructing the remaining subsystems
            // to terminate too.
            let _shut: subsystem::Handle<()> =
                app.add_subsystem_with_custom_eventloop("terminator", |_, _| async {});

            app.main().await
        })
    })
}

#[test]
fn separate_call_and_result() {
    let runtime = helpers::init_test_runtime();
    utils::concurrency::model(move || {
        runtime.block_on(async {
            let mut app = subsystem::Manager::new("app");
            let shutdown = app.make_shutdown_trigger();

            let substr = app.add_subsystem("substr", Substringer::new("abc".into()));

            // The API allows for the submission of closure to call to be separate form retrieval
            // of the result. This task verifies the behavior is as expected.
            tokio::task::spawn(async move {
                // Submit three calls to the substr without waiting for results
                let responses: Vec<_> = (0..3)
                    .map(|i| substr.call(move |this| this.substr(i, i + 1)).response().unwrap())
                    .collect();

                // Expected values
                let expected = ["a", "b", "c"];
                assert_eq!(responses.len(), expected.len());

                // Gather and verify results
                for (response, expected) in responses.into_iter().zip(expected.into_iter()) {
                    assert_eq!(response.await.unwrap(), expected);
                }

                // Shut down the manager once done
                shutdown.initiate();
            });

            app.main().await
        })
    })
}
