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

use anyhow::Context;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use p2p::{interface::p2p_interface::P2pInterface, P2pEvent};
use subsystem::Handle;
use utils::tap_log::TapLog;

use super::{backend_impl::Backend, messages::BackendEvent};

pub struct P2pEventHandler {
    p2p_event_rx: UnboundedReceiver<P2pEvent>,
    event_tx: UnboundedSender<BackendEvent>,
}

impl P2pEventHandler {
    pub async fn new(
        p2p: &Handle<dyn P2pInterface>,
        event_tx: UnboundedSender<BackendEvent>,
    ) -> anyhow::Result<Self> {
        // TODO: Fix race in p2p events subscribe (if some peers are connected before the subscription is complete)

        // TODO: need a way to propagate subsystem initialization errors. E.g. if the p2p port is busy, we'll
        // currently report "Error subscribing to P2P events: Callee subsystem did not respond", which is not
        // very informative.
        // Same for ChainstateEventHandler.

        let (p2p_event_tx, p2p_event_rx) = unbounded_channel();
        let error_context = "Error subscribing to P2P events";
        p2p.call_mut(|this| {
            this.subscribe_to_events(Arc::new(move |p2p_event: P2pEvent| {
                _ = p2p_event_tx
                    .send(p2p_event)
                    .log_err_pfx("P2P subscriber failed to send new event");
            }))
        })
        .await
        .context(error_context)?
        .context(error_context)?;

        Ok(Self {
            p2p_event_rx,
            event_tx,
        })
    }

    pub async fn run(&mut self) {
        // Must be cancel-safe!
        loop {
            let p2p_event_opt = self.p2p_event_rx.recv().await;
            match p2p_event_opt {
                Some(event) => {
                    Backend::send_event(&self.event_tx, BackendEvent::P2p(event));
                }
                None => {
                    // Node is stopped
                    return;
                }
            }
        }
    }
}
