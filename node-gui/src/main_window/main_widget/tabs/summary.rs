// Copyright (c) 2021-2023 RBB S.r.l
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

use std::{fmt::Debug, sync::Arc};

use chainstate::{chainstate_interface::ChainstateInterface, ChainstateEvent};
use common::{
    chain::GenBlock,
    primitives::{BlockHeight, Id},
};
use iced::{
    widget::{container, Column, Scrollable, Text},
    Command, Element,
};
use iced_aw::{tab_bar::TabLabel, Grid};
use subsystem::Handle;
use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    Mutex,
};
use utils::tap_error_log::LogError;

use crate::backend_controller::NodeBackendController;

use super::{Icon, Tab, TabsMessage};

#[derive(Debug, Clone)]
pub enum SummaryMessage {
    Start,
    Ready(RegisteredSubscriptions),
    UpdateState((RegisteredSubscriptions, SummaryWidgetDataUpdate)),
}

#[derive(Debug, Clone)]
pub enum SummaryWidgetDataUpdate {
    TipUpdated((Id<GenBlock>, BlockHeight)),
    NoOp,
}

#[derive(Clone)]
pub struct RegisteredSubscriptions {
    // Unfortunately, GUI messages must support Clone, and async channel receivers are not Clone, so we need this (ugly) Arc.
    #[allow(clippy::type_complexity)]
    chainstate_event_receiver: Arc<Mutex<UnboundedReceiver<(Id<GenBlock>, BlockHeight)>>>,
}

impl Debug for RegisteredSubscriptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisteredSubscriptions")
            .field("chainstate_event_receiver", &self.chainstate_event_receiver)
            .finish()
    }
}

pub struct SummaryTab {
    controller: NodeBackendController,
    current_tip: Option<(Id<GenBlock>, BlockHeight)>,
}

impl SummaryTab {
    pub fn new(controller: NodeBackendController) -> Self {
        SummaryTab {
            controller,
            current_tip: None,
        }
    }

    pub fn start(
        controller: NodeBackendController,
    ) -> impl IntoIterator<Item = Command<SummaryMessage>> {
        [Command::perform(
            Self::initialize_subscriptions(controller.node().chainstate.clone()),
            SummaryMessage::Ready,
        )]
    }

    pub fn update(&mut self, message: SummaryMessage) -> Command<SummaryMessage> {
        match message {
            SummaryMessage::Start => iced::Command::batch(Self::start(self.controller.clone())),
            SummaryMessage::Ready(subs) => Command::perform(
                Self::event_loop_single_iteration(subs),
                SummaryMessage::UpdateState,
            ),
            SummaryMessage::UpdateState((subs, new_data)) => {
                match new_data {
                    SummaryWidgetDataUpdate::TipUpdated(tip) => self.current_tip = Some(tip),
                    SummaryWidgetDataUpdate::NoOp => (),
                }
                Command::perform(
                    Self::event_loop_single_iteration(subs),
                    SummaryMessage::UpdateState,
                )
            }
        }
    }

    async fn subscribe_to_chainstate(
        chainstate_handle: Handle<Box<dyn ChainstateInterface>>,
        chainstate_sender: UnboundedSender<(Id<GenBlock>, BlockHeight)>,
    ) {
        chainstate_handle
            .call_mut(|this| {
                let subscribe_func =
                    Arc::new(
                        move |chainstate_event: ChainstateEvent| match chainstate_event {
                            ChainstateEvent::NewTip(block_id, block_height) => {
                                _ = chainstate_sender
                                    .send((block_id.into(), block_height))
                                    .log_err_pfx("Chainstate subscriber failed to send new tip");
                            }
                        },
                    );

                this.subscribe_to_events(subscribe_func);
            })
            .await
            .expect("Failed to subscribe to chainstate");
    }

    async fn initialize_subscriptions(
        chainstate_handle: Handle<Box<dyn ChainstateInterface>>,
    ) -> RegisteredSubscriptions {
        let (chainstate_event_sender, chainstate_event_receiver) =
            tokio::sync::mpsc::unbounded_channel();

        Self::subscribe_to_chainstate(chainstate_handle.clone(), chainstate_event_sender).await;

        RegisteredSubscriptions {
            chainstate_event_receiver: Arc::new(chainstate_event_receiver.into()),
        }
    }

    async fn event_loop_single_iteration(
        subs: RegisteredSubscriptions,
    ) -> (RegisteredSubscriptions, SummaryWidgetDataUpdate) {
        let mut chainstate_event_receiver = subs.chainstate_event_receiver.lock().await;
        tokio::select! {
            event = (*chainstate_event_receiver).recv() => {
                drop(chainstate_event_receiver);
                if let Some((block_id, block_height)) = event {
                    std::thread::sleep(std::time::Duration::from_millis(3000));
                    println!("Updating state: new tip: {:?} at height {:?}", block_id, block_height);
                    (subs, SummaryWidgetDataUpdate::TipUpdated((block_id, block_height)))
                } else {
                    (subs, SummaryWidgetDataUpdate::NoOp)
                }
            }
        }
    }
}

impl Tab for SummaryTab {
    type Message = TabsMessage;

    fn title(&self) -> String {
        String::from("Summary")
    }

    fn tab_label(&self) -> TabLabel {
        // TabLabel::Text(self.title())
        TabLabel::IconText(Icon::User.into(), self.title())
    }

    fn content(&self) -> Element<'_, Self::Message> {
        let (best_id, best_height) = self
            .current_tip
            .unwrap_or((self.controller.chain_config().genesis_block_id(), 0.into()));

        let grid = Grid::with_columns(2);
        let grid = grid.push(Text::new("Best block id ")).push(Text::new(best_id.to_string()));
        let grid = grid
            .push(Text::new("Best block height "))
            .push(Text::new(best_height.to_string()));

        let main_widget: Element<'_, Self::Message> = Column::new()
            .spacing(15)
            .max_width(600)
            .align_items(iced::Alignment::Center)
            .push(grid)
            .into();

        let main_widget = Scrollable::new(main_widget);

        let c = container(main_widget);

        c.into()
    }
}
