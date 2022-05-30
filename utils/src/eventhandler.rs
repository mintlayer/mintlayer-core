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

    pub fn broadcast(&self, event: E) {
        self.event_subscribers.iter().cloned().for_each(|handler| {
            let tracker = self.wait_for_events.count_one();
            let event = event.clone();
            self.events_broadcaster.spawn(move || {
                let tracker = tracker;
                assert!(tracker.value() > 0);
                handler(event)
            })
        })
    }
}
