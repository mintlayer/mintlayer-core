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
use crate::{
    error::{self, P2pError},
    net::libp2p::{
        backend::{Backend, PendingState},
        types,
    },
};
use libp2p::identify::IdentifyEvent;
use logging::log;

impl Backend {
    pub async fn on_identify_event(&mut self, event: IdentifyEvent) -> error::Result<()> {
        match event {
            IdentifyEvent::Received { peer_id, info } => {
                match self.pending_conns.remove(&peer_id) {
                    None => {
                        log::error!("pending connection for peer {:?} does not exist", peer_id);
                        Ok(())
                    }
                    Some(PendingState::Dialed { tx }) => {
                        log::error!("received peer info before connection was established");
                        Ok(())
                    }
                    Some(PendingState::OutboundAccepted { tx }) => {
                        tx.send(Ok(info)).map_err(|_| P2pError::ChannelClosed)
                    }
                    Some(PendingState::InboundAccepted { addr }) => self
                        .conn_tx
                        .send(types::ConnectivityEvent::ConnectionAccepted {
                            peer_info: Box::new(info),
                        })
                        .await
                        .map_err(|_| P2pError::ChannelClosed),
                }
            }
            IdentifyEvent::Error { peer_id, error } => {
                log::error!("identify error: {:?}", error);
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn it_works() {}
}
