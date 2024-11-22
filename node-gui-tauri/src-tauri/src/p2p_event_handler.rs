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

use super::messages::BackendEvent;
use once_cell::sync::OnceCell;
use p2p::{interface::p2p_interface::P2pInterface, P2pEvent};
use std::sync::Arc;
use subsystem::Handle;
use tauri::{AppHandle, Emitter};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use utils::tap_log::TapLog;

pub struct P2pEventHandler {
    p2p_event_rx: UnboundedReceiver<P2pEvent>,
}

impl P2pEventHandler {
    pub async fn new(p2p: &Handle<dyn P2pInterface>) -> Self {
        // TODO: Fix race in p2p events subscribe (if some peers are connected before the subscription is complete)

        let (p2p_event_tx, p2p_event_rx) = unbounded_channel();
        p2p.call_mut(|this| {
            this.subscribe_to_events(Arc::new(move |p2p_event: P2pEvent| {
                _ = p2p_event_tx
                    .send(p2p_event)
                    .log_err_pfx("P2P subscriber failed to send new event");
            }))
        })
        .await
        .expect("Failed to subscribe to P2P event")
        .expect("Failed to subscribe to P2P event");

        Self { p2p_event_rx }
    }

    pub async fn run(&mut self, global_app_handle: OnceCell<AppHandle>) {
        // Must be cancel-safe!
        loop {
            let p2p_event_opt = self.p2p_event_rx.recv().await;
            match p2p_event_opt {
                Some(event) => {
                    let event_data = BackendEvent::P2p(event);
                    if let Some(app_handle) = global_app_handle.get() {
                        app_handle.emit("p2p_event", event_data).unwrap();
                    }
                }
                None => {
                    // Node is stopped
                    return;
                }
            }
        }
    }
}
