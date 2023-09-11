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

#![cfg(all(feature = "time", not(loom)))]

// A subsystem that blocks the shutdown process.
struct NoExit;

#[async_trait::async_trait]
impl subsystem::Subsystem for NoExit {
    type Interface = Self;

    fn interface_ref(&self) -> &Self {
        self
    }

    fn interface_mut(&mut self) -> &mut Self {
        self
    }

    async fn shutdown(self) {
        std::future::pending().await
    }
}

#[tokio::test]
async fn shutdown_timeout() {
    testing_logger::setup();

    let config = subsystem::ManagerConfig::new("timeout_test")
        .with_shutdown_timeout_per_subsystem(std::time::Duration::from_secs(1));
    let mut man = subsystem::Manager::new_with_config(config);

    man.add_custom_subsystem("does_not_want_to_exit", |_| {
        std::future::ready(Result::<_, std::convert::Infallible>::Ok(NoExit))
    });
    man.make_shutdown_trigger().initiate();
    man.main().await;

    testing_logger::validate(|logs| {
        assert!(logs.iter().any(|entry| entry.body.contains("shutdown timed out")));
    });
}
