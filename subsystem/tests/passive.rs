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

#![allow(clippy::new_without_default)]

mod helpers;

// The substringer passive subsystem (for testing)
pub struct Substringer {
    value: String,
}

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

    async fn run(&self, _: subsystem::CallRequest<()>, _: subsystem::ShutdownRequest) {
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
    common::concurrency::model(move || {
        runtime.block_on(async {
            let app = subsystem::Manager::new("app");

            let substr = app.start("substr", Substringer::new("abc".into()));
            let counter = app.start("counter", Counter::new());

            let tester = Tester::new(substr, counter);
            app.start_raw("test", |call_rq, shut_rq| async move {
                tester.run(call_rq, shut_rq).await
            });

            app.main().await
        })
    })
}

#[test]
fn basic_passive_shutdown() {
    let runtime = helpers::init_test_runtime();
    common::concurrency::model(move || {
        runtime.block_on(async {
            let app = subsystem::Manager::new("app");

            let _substr = app.start("substr", Substringer::new("abc".into()));
            let _counter = app.start("counter", Counter::new());

            // Start a subsystem that immediately terminates, instructing the remaining subsystems
            // to terminate too.
            let _shut: subsystem::Handle<()> = app.start_raw("terminator", |_, _| async {});

            app.main().await
        })
    })
}
