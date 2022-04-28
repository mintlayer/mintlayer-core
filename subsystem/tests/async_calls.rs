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

use subsystem::subsystem::{CallRequest, CallError};

mod helpers;

// Logger (as a subsystem)
pub struct Logger {
    prefix: String,
}

impl subsystem::Subsystem for Logger {}

impl Logger {
    fn new(prefix: String) -> Self {
        Logger { prefix }
    }

    fn write(&self, message: &str) {
        logging::log::warn!("{}: {}", self.prefix, message);
    }
}

// Logging counter
pub struct Counter {
    count: u64,
    logger: subsystem::Handle<Logger>,
}

impl subsystem::Subsystem for Counter {}

impl Counter {
    fn new(logger: subsystem::Handle<Logger>) -> Self {
        let count = 0u64;
        Self { count, logger }
    }

    async fn bump(&mut self) -> Result<u64, CallError> {
        self.count += 1;
        let message = format!("Bumped counter to {}", self.count);
        self.logger
            .call(move |logger| logger.write(&message))
            .await
            .map(|()| self.count)
    }
}

#[test]
fn async_calls() {
    let runtime = helpers::init_test_runtime();
    common::concurrency::model(move || {
        runtime.block_on(async {
            let app = subsystem::Manager::new("app");
            let logger = app.start("logger", Logger::new("logging".to_string()));
            let counter = app.start("counter", Counter::new(logger.clone()));

            app.start_raw(
                "test",
                |_call_rq: CallRequest<()>, _shut_rq| async move {
                    logger.call(|l| l.write("starting")).await.unwrap();

                    // Bump the counter twice
                    let res = counter.call_async_mut(|c| Box::pin(c.bump())).await;
                    assert_eq!(res, Ok(Ok(1)));
                    let res = counter.call_async_mut(|c| Box::pin(c.bump())).await;
                    assert_eq!(res, Ok(Ok(2)));

                    logger.call(|l| l.write("done")).await.unwrap();
                },
            );

            app.main().await
        })
    })
}
