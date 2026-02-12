// Copyright (c) 2022 RBB S.r.l
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

use crate::blockuntilzero::BlockUntilZero;

use crate::sync::atomic::AtomicI32;
use std::sync::Arc;

pub type EventHandler<E> = Arc<dyn Fn(E) + Send + Sync>;

pub struct EventsController<E> {
    event_subscribers: Vec<EventHandler<E>>,
    events_broadcaster: slave_pool::ThreadPool,
    wait_for_events: BlockUntilZero<AtomicI32>,
}

impl<E: Clone + Send + Sync + 'static> EventsController<E> {
    pub fn new() -> Self {
        let events_broadcaster = slave_pool::ThreadPool::new();
        // TODO: `slave_pool::ThreadPool` does not increase the number of threads automatically,
        // so we'll always have exactly one thread here. Moreover, increasing the number of threads
        // would allow events to be handled in a wrong order. So the thread pool is completely
        // useless here and should be replaced with a single thread.
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

#[cfg(test)]
mod tests {
    use std::{
        ops::Deref as _,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use super::*;

    // Check that a handler won't be called for a later event if its call for an earlier
    // event hasn't finished yet.
    #[test]
    fn events_ordering() {
        #[derive(Eq, PartialEq, Copy, Clone, Debug)]
        enum Event {
            A,
            B,
        }

        let mut controller = EventsController::<Event>::new();
        let handled_events = Arc::new(Mutex::new(Vec::new()));

        controller.subscribe_to_events({
            let handled_events = Arc::clone(&handled_events);

            Arc::new(move |event| {
                match event {
                    Event::A => {
                        std::thread::sleep(Duration::from_millis(500));
                    }
                    Event::B => {}
                }

                handled_events.lock().unwrap().push(event);
            })
        });

        controller.broadcast(Event::A);
        controller.broadcast(Event::B);
        controller.wait_for_all_events();

        assert_eq!(
            handled_events.lock().unwrap().deref(),
            &[Event::A, Event::B]
        );
    }
}
