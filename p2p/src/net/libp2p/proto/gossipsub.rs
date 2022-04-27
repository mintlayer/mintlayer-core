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
use crate::{
    error::{self, P2pError},
    message,
    net::libp2p::{backend::Backend, types},
};
use libp2p::gossipsub::GossipsubEvent;
use logging::log;
use parity_scale_codec::Decode;

impl Backend {
    pub async fn on_gossipsub_event(&mut self, event: GossipsubEvent) -> error::Result<()> {
        match event {
            GossipsubEvent::Message {
                propagation_source,
                message_id,
                message,
            } => {
                let topic = match message.topic.clone().try_into() {
                    Ok(topic) => topic,
                    Err(e) => {
                        log::warn!("failed to convert topic ({:?}): {}", message.topic, e);
                        return Ok(());
                    }
                };

                let message = match message::Message::decode(&mut &message.data[..]) {
                    Ok(data) => data,
                    Err(e) => {
                        log::warn!("failed to decode gossipsub message: {:?}", e);
                        return Ok(());
                    }
                };

                log::trace!(
                    "message ({:#?}) received from gossipsub topic {:?}",
                    message,
                    topic
                );

                self.gossip_tx
                    .send(types::PubSubEvent::MessageReceived {
                        peer_id: propagation_source,
                        topic,
                        message,
                        message_id,
                    })
                    .await
                    .map_err(|_| P2pError::ChannelClosed)
            }
            e => {
                log::info!("unhandle event: {:?}", e);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn it_works() {}
}
