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

use std::{sync::Arc, time::Duration};

use subsystem::wrappers;
use tokio::sync::{watch, Mutex};
use utils::{set_flag::SetFlag, tokio_spawn};

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
    let mut mgr = subsystem::Manager::new_with_config(config);

    mgr.add_custom_subsystem("does_not_want_to_exit", |_, _| {
        std::future::ready(Result::<_, std::convert::Infallible>::Ok(NoExit))
    });
    mgr.make_shutdown_trigger().initiate();
    mgr.main().await;

    testing_logger::validate(|logs| {
        assert!(logs.iter().any(|entry| entry.body.contains("shutdown timed out")));
    });
}

// Check that the "shutdown initiated" flag that is passed to the subsystem's init closure
// is indeed set when shutdown is initiated.
#[tokio::test]
async fn shutdown_flag_set() {
    let mut mgr = subsystem::Manager::new("test");

    let shutdown_initiated_rx_shared: Arc<Mutex<Option<watch::Receiver<SetFlag>>>> =
        Arc::new(Mutex::new(None));

    mgr.add_custom_subsystem("test", {
        let shutdown_initiated_rx_shared = Arc::clone(&shutdown_initiated_rx_shared);
        move |_, shutdown_initiated_rx| async move {
            *shutdown_initiated_rx_shared.lock().await = Some(shutdown_initiated_rx);
            Result::<_, std::convert::Infallible>::Ok(wrappers::Direct::new(()))
        }
    });

    let shutdown_trigger = mgr.make_shutdown_trigger();
    let mgr_join_handle = tokio_spawn(mgr.main(), "mgr main");

    tokio::time::timeout(Duration::from_secs(10), async {
        while shutdown_initiated_rx_shared.lock().await.is_none() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();

    let mut shutdown_initiated_rx = shutdown_initiated_rx_shared.lock().await.take().unwrap();

    tokio::time::timeout(Duration::from_millis(500), async {
        shutdown_initiated_rx.changed().await.unwrap()
    })
    .await
    .unwrap_err();

    shutdown_trigger.initiate();

    tokio::time::timeout(Duration::from_secs(10), async {
        shutdown_initiated_rx.changed().await.unwrap()
    })
    .await
    .unwrap();

    let flag = shutdown_initiated_rx.borrow();
    assert!(flag.test());

    mgr_join_handle.await.unwrap();
}
