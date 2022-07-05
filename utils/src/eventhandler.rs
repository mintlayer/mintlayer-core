// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::blockuntilzero::BlockUntilZero;

use std::sync::{atomic::AtomicI32, Arc};

pub type EventHandler<E> = Arc<dyn Fn(E) + Send + Sync>;

pub struct EventsController<E> {
    event_subscribers: Vec<EventHandler<E>>,
    events_broadcaster: slave_pool::ThreadPool,
    wait_for_events: BlockUntilZero<AtomicI32>,
}

impl<E: Clone + Send + Sync + 'static> EventsController<E> {
    pub fn new() -> Self {
        let events_broadcaster = slave_pool::ThreadPool::new();
        events_broadcaster.set_threads(1).expect("Event thread-pool starting failed");
        Self {
            event_subscribers: Vec::new(),
            events_broadcaster,
            wait_for_events: BlockUntilZero::new(),
        }
    }

    pub fn subscribers(&self) -> &Vec<EventHandler<E>> {
        &self.event_subscribers
    }

    pub fn subscribe_to_events(&mut self, handler: EventHandler<E>) {
        self.event_subscribers.push(handler)
    }

    pub fn wait_for_all_events(&self) {
        self.wait_for_events.wait_for_zero();
    }

    fn broadcast_spawn_call(&self, event: E, handler: EventHandler<E>) {
        let tracker = self.wait_for_events.count_one();
        self.events_broadcaster.spawn(move || {
            let tracker = tracker;
            assert!(tracker.value() > 0);
            handler(event)
        })
    }

    pub fn broadcast(&self, event: E) {
        self.event_subscribers.iter().cloned().for_each(|handler| {
            let event = event.clone();
            self.broadcast_spawn_call(event, handler)
        })
    }
}

impl<E: Clone + Send + Sync + 'static> Default for EventsController<E> {
    fn default() -> Self {
        Self::new()
    }
}

// TODO: add tests for events
