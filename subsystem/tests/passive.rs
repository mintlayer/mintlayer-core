// Copyright (c) 2022-2023 RBB S.r.l
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
use subsystem::subsystem::{CallRequest, ShutdownRequest};

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
            app.add_subsystem_with_custom_eventloop("test", |call_rq, shut_rq| async move {
                tester.run(call_rq, shut_rq).await
            });

            app.main().await
        })
    })
}
