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

#![allow(clippy::new_without_default)]

use subsystem::subsystem::{CallRequest, ShutdownRequest};

mod helpers;

// The substringer passive subsystem (for testing)
pub struct Substringer {
    value: String,
}

impl subsystem::Subsystem for Substringer {}

impl Substringer {
    pub fn new(value: String) -> Self {
        Self { value }
    }

    pub fn append_get(&mut self, other: &str) -> String {
        self.value += other;
        self.value.clone()
    }

    pub fn substr(&self, begin: usize, end: usize) -> String {
        self.value.get(begin..end).map_or_else(String::new, str::to_string)
    }

    pub fn size(&self) -> usize {
        self.value.len()
    }
}

// The counter passive subsystem (for testing)
pub struct Counter {
    value: u64,
}

impl subsystem::Subsystem for Counter {}

impl Counter {
    pub fn new() -> Self {
        Self { value: 13 }
    }

    pub fn get(&self) -> u64 {
        self.value
    }

    pub fn add_and_get(&mut self, amount: u64) -> u64 {
        self.value += amount;
        self.value
    }
}

// The subsystem testing the other two subsystems
pub struct Tester {
    substringer: subsystem::Handle<Substringer>,
    counter: subsystem::Handle<Counter>,
}

impl Tester {
    fn new(
        substringer: subsystem::Handle<Substringer>,
        counter: subsystem::Handle<Counter>,
    ) -> Self {
        Self {
            substringer,
            counter,
        }
    }

    async fn run(&self, _: CallRequest<()>, _: ShutdownRequest) {
        let res0 = self.substringer.call_mut(|this| this.append_get("xyz"));
        assert_eq!(res0.await, Ok("abcxyz".to_string()));
        assert_eq!(self.substringer.call(Substringer::size).await, Ok(6));

        let res1 = self.substringer.call(|this| this.substr(2, 5));
        assert_eq!(res1.await, Ok("cxy".to_string()));

        let res2 = self.counter.call(Counter::get);
        assert_eq!(res2.await, Ok(13));

        let res3 = self.counter.call_mut(|this| this.add_and_get(3));
        assert_eq!(res3.await, Ok(16));
    }
}

#[test]
fn basic_passive_subsystem() {
    let runtime = helpers::init_test_runtime();
    utils::concurrency::model(move || {
        runtime.block_on(async {
            let mut app = subsystem::Manager::new("app");

            let substr = app.add_subsystem("substr", Substringer::new("abc".into()));
            let counter = app.add_subsystem("counter", Counter::new());

            let tester = Tester::new(substr, counter);
            app.add_raw_subsystem("test", |call_rq, shut_rq| async move {
                tester.run(call_rq, shut_rq).await
            });

            app.main().await
        })
    })
}

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
            let _shut: subsystem::Handle<()> = app.add_raw_subsystem("terminator", |_, _| async {});

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
