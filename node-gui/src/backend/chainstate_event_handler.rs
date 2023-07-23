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

use std::sync::Arc;

use chainstate::{chainstate_interface::ChainstateInterface, ChainstateEvent};
use subsystem::Handle;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use utils::tap_error_log::LogError;

use super::{messages::BackendEvent, Backend};

pub struct ChainstateEventHandler {
    chainstate_event_rx: UnboundedReceiver<ChainstateEvent>,
    event_tx: UnboundedSender<BackendEvent>,
}

impl ChainstateEventHandler {
    pub async fn new(
        chainstate: &Handle<Box<dyn ChainstateInterface>>,
        event_tx: UnboundedSender<BackendEvent>,
    ) -> Self {
        let (chainstate_event_tx, chainstate_event_rx) = unbounded_channel();
        chainstate
            .call_mut(|this| {
                this.subscribe_to_events(Arc::new(move |chainstate_event: ChainstateEvent| {
                    _ = chainstate_event_tx
                        .send(chainstate_event)
                        .log_err_pfx("Chainstate subscriber failed to send new tip");
                }));
            })
            .await
            .expect("Failed to subscribe to chainstate");

        Self {
            chainstate_event_rx,
            event_tx,
        }
    }

    pub async fn run(&mut self) {
        // Must be cancel-safe!
        loop {
            let chainstate_event_opt = self.chainstate_event_rx.recv().await;
            match chainstate_event_opt {
                Some(event) => {
                    Backend::send_event(&self.event_tx, BackendEvent::Chainstate(event));
                }
                None => {
                    // Node is stopped
                    return;
                }
            }
        }
    }
}
