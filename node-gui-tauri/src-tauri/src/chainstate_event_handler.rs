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

use super::messages::BackendEvent;
use chainstate::ChainstateEvent;
use once_cell::sync::OnceCell;
use tauri::{AppHandle, Emitter as _};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use utils::tap_log::TapLog;

pub struct ChainstateEventHandler {
    chainstate: chainstate::ChainstateHandle,
    chainstate_event_rx: UnboundedReceiver<ChainstateEvent>,
    event_tx: UnboundedSender<BackendEvent>,
    chain_info_updated: bool,
}

impl ChainstateEventHandler {
    pub async fn new(
        chainstate: chainstate::ChainstateHandle,
        event_tx: UnboundedSender<BackendEvent>,
    ) -> Self {
        let (chainstate_event_tx, chainstate_event_rx) = unbounded_channel();
        chainstate
            .call_mut(|this| {
                this.subscribe_to_subsystem_events(Arc::new(
                    move |chainstate_event: ChainstateEvent| {
                        _ = chainstate_event_tx
                            .send(chainstate_event)
                            .log_err_pfx("Chainstate subscriber failed to send new tip");
                    },
                ));
            })
            .await
            .expect("Failed to subscribe to chainstate");

        Self {
            chainstate,
            chainstate_event_rx,
            event_tx,
            chain_info_updated: false,
        }
    }

    pub async fn run(&mut self, global_app_handle: OnceCell<AppHandle>) {
        // Must be cancel-safe!
        loop {
            // The `chain_info_updated` field is needed because `run` must be cancel-safe.
            // The `run` call can be canceled between `await` points, but we need to update the UI after receiving `NewTip` event.
            if self.chain_info_updated {
                let chain_info = self
                    .chainstate
                    .call(|this| this.info().expect("Chainstate::info should not fail"))
                    .await
                    .expect("Chainstate::info should not fail");
                let event_data = BackendEvent::ChainInfo(chain_info);
                if let Some(app_handle) = global_app_handle.get() {
                    app_handle.emit("chain_state_event", event_data).unwrap();
                }
                self.chain_info_updated = false;
            }

            let chainstate_event_opt = self.chainstate_event_rx.recv().await;
            match chainstate_event_opt {
                Some(event) => match event {
                    ChainstateEvent::NewTip(_, _) => {
                        self.chain_info_updated = true;
                    }
                },
                None => {
                    // Node is stopped
                    return;
                }
            }
        }
    }
}
