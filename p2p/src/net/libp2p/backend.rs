// Copyright (c) 2021 Protocol Labs
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
// Author(s): A. Altonen
use crate::net::libp2p::common;
use futures::StreamExt;
use libp2p::swarm::Swarm;
use tokio::sync::mpsc::{Receiver, Sender};

pub struct Backend {
    swarm: Swarm<common::ComposedBehaviour>,
    cmd_rx: Receiver<common::Command>,
    _event_tx: Sender<common::Event>,
}

impl Backend {
    pub fn new(
        swarm: Swarm<common::ComposedBehaviour>,
        cmd_rx: Receiver<common::Command>,
        event_tx: Sender<common::Event>,
    ) -> Self {
        Self {
            swarm,
            cmd_rx,
            _event_tx: event_tx,
        }
    }

    pub async fn run(&mut self) {
        loop {
            tokio::select! {
                _event = self.swarm.next() => self.on_event().await,
                command = self.cmd_rx.recv() => match command {
                    Some(_cmd) => self.on_command().await,
                    None => return,
                },
            }
        }
    }

    async fn on_event(&mut self) {
        todo!();
    }

    async fn on_command(&mut self) {
        todo!();
    }
}
