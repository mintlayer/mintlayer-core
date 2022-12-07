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

use logging::log;
use std::time::{Duration, Instant};

use subsystem::subsystem::{CallRequest, ShutdownRequest};

struct Stopwatch(Instant);

impl Stopwatch {
    async fn start(mut call_rq: CallRequest<Self>, mut shutdown_rq: ShutdownRequest) {
        let mut stopwatch = Self::new(Instant::now());
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        loop {
            tokio::select! {
                () = shutdown_rq.recv() => break,
                call = call_rq.recv() => call(&mut stopwatch).await,
                _ = interval.tick() => stopwatch.report("Running"),
            }
        }
        stopwatch.report("Elapsed");
    }

    fn new(start: Instant) -> Self {
        Self(start)
    }

    fn elapsed(&self) -> Duration {
        Instant::now().duration_since(self.0)
    }

    fn report(&self, msg: &str) {
        log::error!("{} {:?}", msg, self.elapsed());
    }
}

#[tokio::main]
async fn main() {
    logging::init_logging::<&std::path::Path>(None);

    let mut app = subsystem::Manager::new("toplevel");
    app.install_signal_handlers();
    app.add_subsystem_with_custom_eventloop("watch", Stopwatch::start);
    app.main().await
}
