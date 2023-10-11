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

#[test]
fn basic_passive_subsystem() {
    let runtime = helpers::init_test_runtime();
    utils::concurrency::model(move || {
        runtime.block_on(async {
            let mut app = subsystem::Manager::new("app");

            let substr = app.add_direct_subsystem("substr", Substringer::new("abc".into()));
            let counter = app.add_direct_subsystem("counter", Counter::new());
            let shutdown = app.make_shutdown_trigger();

            let tester = tokio::spawn(async move {
                let res0 = substr.call_mut(|this| this.append_get("xyz"));
                assert_eq!(res0.await, Ok("abcxyz".to_string()));
                assert_eq!(substr.call(Substringer::size).await, Ok(6));

                let res1 = substr.call(|this| this.substr(2, 5));
                assert_eq!(res1.await, Ok("cxy".to_string()));

                let res2 = counter.call(Counter::get);
                assert_eq!(res2.await, Ok(13));

                let res3 = counter.call_mut(|this| this.add_and_get(3));
                assert_eq!(res3.await, Ok(16));

                shutdown.initiate();
            });

            let _ = tokio::join!(app.main(), tester);
        })
    })
}
