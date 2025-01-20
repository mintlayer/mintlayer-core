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

use anyhow::Context as _;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use chainstate::ChainstateEvent;
use utils::tap_log::TapLog;

use super::{backend_impl::Backend, messages::BackendEvent};

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
    ) -> anyhow::Result<Self> {
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
            .context("Error subscribing to chainstate events")?;

        Ok(Self {
            chainstate,
            chainstate_event_rx,
            event_tx,
            chain_info_updated: false,
        })
    }

    pub async fn run(&mut self) {
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
                Backend::send_event(&self.event_tx, BackendEvent::ChainInfo(chain_info));
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
