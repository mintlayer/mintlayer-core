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
use subsystem::{
    blocking::BlockingHandle,
    subsystem::{CallRequest, ShutdownRequest},
};

// The subsystem testing the other two subsystems
pub struct Tester {
    substringer: BlockingHandle<Substringer>,
    counter: BlockingHandle<Counter>,
}

impl Tester {
    fn new(substringer: BlockingHandle<Substringer>, counter: BlockingHandle<Counter>) -> Self {
        Self {
            substringer,
            counter,
        }
    }

    async fn run(self, _: CallRequest<()>, _shutdown: ShutdownRequest) {
        let res0 = self.substringer.call_mut(|this| this.append_get("xyz"));
        assert_eq!(res0, Ok("abcxyz".to_string()));
        assert_eq!(self.substringer.call(Substringer::size), Ok(6));
        tokio::task::yield_now().await;

        let res1 = self.substringer.call(|this| this.substr(2, 5));
        assert_eq!(res1, Ok("cxy".to_string()));
        tokio::task::yield_now().await;

        let res2 = self.counter.call(Counter::get);
        assert_eq!(res2, Ok(13));
        tokio::task::yield_now().await;

        let res3 = self.counter.call_mut(|this| this.add_and_get(3));
        assert_eq!(res3, Ok(16));
    }
}

static_assertions::assert_impl_all!(Tester: Send);

#[test]
fn basic_passive_subsystem_blocking() {
    let runtime = helpers::init_test_runtime();
    utils::concurrency::model(move || {
        runtime.block_on(async {
            let mut app = subsystem::Manager::new("app");

            let substr = app.add_subsystem("substr", Substringer::new("abc".into()));
            let counter = app.add_subsystem("counter", Counter::new());

            let tester1 = Tester::new(substr.into(), counter.into());
            app.add_subsystem_with_custom_eventloop("test", |call_rq, shut_rq| async move {
                tester1.run(call_rq, shut_rq).await
            });

            app.main().await
        })
    })
}

fn tester_worker_thread(
    substringer: BlockingHandle<Substringer>,
    counter: BlockingHandle<Counter>,
    shutdown: subsystem::manager::ShutdownTrigger,
) {
    let res0 = substringer.call_mut(|this| this.append_get("xyz"));
    assert_eq!(res0, Ok("abcxyz".to_string()));
    assert_eq!(substringer.call(Substringer::size), Ok(6));

    let res1 = substringer.call(|this| this.substr(2, 5));
    assert_eq!(res1, Ok("cxy".to_string()));

    let res2 = counter.call(Counter::get);
    assert_eq!(res2, Ok(13));

    let res3 = counter.call_mut(|this| this.add_and_get(3));
    assert_eq!(res3, Ok(16));

    shutdown.initiate();
}

#[test]
fn basic_passive_subsystem_called_from_separate_thread() {
    let runtime = helpers::init_test_runtime();
    utils::concurrency::model(move || {
        let mut app = subsystem::Manager::new("app");

        let substr =
            BlockingHandle::new(app.add_subsystem("substr", Substringer::new("abc".into())));
        let counter = BlockingHandle::new(app.add_subsystem("counter", Counter::new()));
        let shutdown = app.make_shutdown_trigger();

        let tester_thread =
            utils::thread::spawn(move || tester_worker_thread(substr, counter, shutdown));

        runtime.block_on(app.main());
        tester_thread.join().expect("tester to finish successfully");
    })
}
