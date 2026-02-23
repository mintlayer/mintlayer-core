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

use std::{
    convert::Infallible,
    time::{Duration, Instant},
};

use tokio::sync::watch;

use logging::log;
use utils::set_flag::SetFlag;

struct Stopwatch {
    start: Instant,
    tick_task: tokio::task::JoinHandle<()>,
}

impl Stopwatch {
    #[allow(clippy::unused_async)]
    async fn init(
        handle: subsystem::SubmitOnlyHandle<Self>,
        _shutdown_initiated_rx: watch::Receiver<SetFlag>,
    ) -> Result<Self, Infallible> {
        let start = Instant::now();
        let tick_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            loop {
                interval.tick().await;
                let _ = handle.submit(|this| this.report("Running"));
            }
        });

        Ok(Self { start, tick_task })
    }

    fn elapsed(&self) -> Duration {
        Instant::now().duration_since(self.start)
    }

    fn report(&self, msg: &str) {
        log::error!("{} {:?}", msg, self.elapsed());
    }
}

#[async_trait::async_trait]
impl subsystem::Subsystem for Stopwatch {
    type Interface = Self;

    fn interface_ref(&self) -> &Self {
        self
    }

    fn interface_mut(&mut self) -> &mut Self {
        self
    }

    async fn shutdown(self) {
        self.report("Elapsed");
        self.tick_task.abort();
        let _ = self.tick_task.await;
    }
}

#[tokio::main]
async fn main() {
    logging::init_logging();

    let config = subsystem::ManagerConfig::new("toplevel").enable_signal_handlers();
    let mut app = subsystem::Manager::new_with_config(config);
    app.add_custom_subsystem("stopwatch", Stopwatch::init);
    app.main().await
}
