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

use std::sync::mpsc;

use utils::tap_error_log::LogError;

use super::OrphanBlocksPool;

type RemoteCall = Option<Box<dyn FnOnce(&mut OrphanBlocksPool) + Send>>;

/// A tool that runs OrphanBlocksPool in a separate thread
/// and supports remote calls to it, such that it never
/// needs to be moved among threads.
pub struct OrphansProxy {
    thread_handle: Option<std::thread::JoinHandle<()>>,
    tx: mpsc::Sender<RemoteCall>,
}

impl OrphansProxy {
    #[allow(dead_code)]
    pub fn new(max_orphans: usize) -> Self {
        let (tx, rx) = mpsc::channel();
        let stop_control = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_handle = Some(std::thread::spawn(move || {
            let mut orphans_pool = OrphanBlocksPool::new(max_orphans);
            let receiver: mpsc::Receiver<RemoteCall> = rx;
            while !stop_control.load(std::sync::atomic::Ordering::Relaxed) {
                match receiver.recv() {
                    Ok(f) => match f {
                        Some(func) => func(&mut orphans_pool),
                        None => break,
                    },
                    Err(_) => break,
                }
            }
        }));
        Self { thread_handle, tx }
    }

    #[allow(dead_code)]
    pub fn call<R: Send + 'static>(
        &self,
        f: impl FnOnce(&OrphanBlocksPool) -> R + Send + 'static,
    ) -> oneshot::Receiver<R> {
        self.call_mut(|this| f(this))
    }

    #[allow(dead_code)]
    pub fn call_mut<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut OrphanBlocksPool) -> R + Send + 'static,
    ) -> oneshot::Receiver<R> {
        let (tx, rx) = oneshot::channel::<R>();
        let _ = self
            .tx
            .send(Some(Box::new(move |subsys| {
                let result = f(subsys);
                tx.send(result).unwrap();
            })))
            .log_err();
        rx
    }
}

impl Drop for OrphansProxy {
    fn drop(&mut self) {
        self.tx.send(None).expect("Failed to send stop control message");
        let mut to_kill: Option<std::thread::JoinHandle<()>> = None;
        std::mem::swap(&mut self.thread_handle, &mut to_kill);
        to_kill.expect("Must exist after the swap").join().expect("Join failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orphans_proxy_control() {
        let orphans_proxy = OrphansProxy::new(500);
        assert_eq!(orphans_proxy.call(|o| o.len()).recv().unwrap(), 0);
    }
}
