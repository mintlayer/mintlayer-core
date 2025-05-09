// Copyright (c) 2025 RBB S.r.l
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

use std::{
    fmt::Write as _,
    sync::Arc,
    thread::{sleep, JoinHandle},
    time::Duration,
};

use trezor_client::protos::{
    debug_link_decision::DebugButton, debug_link_get_state::DebugWaitType, DebugLinkDecision,
    DebugLinkGetState,
};

use logging::log;
use test_utils::threading::spawn_thread_aborting_on_panic;
use utils::atomics::RelaxedAtomicBool;

use super::{find_test_device, get_response, send_message, should_auto_confirm};

/// Spawn a new thread that constantly confirms dialogs on the Trezor screen, to avoid the need of
/// human interaction when running the tests.
///
/// Note:
/// 1) The function calls `find_test_device` and expects it to find the same device/emulator that
///    the tests will use. This won't work properly if more than 1 device/emulator is available.
/// 2) The current approach is rather crude. Ideally, tests themselves should be aware of the layout
///    changes that their actions produce and emit only a specific number of confirmations.
///    Also, it'd be nice to have some negative tests, where a flow is cancelled and the function
///    being testes is expected to fail in a specific way.
///
/// TODO: address the above notes.
pub fn maybe_spawn_auto_confirmer() -> Option<AutoConfirmerJoinHandle> {
    if !should_auto_confirm() {
        return None;
    }

    let done_flag = Arc::new(RelaxedAtomicBool::new(false));

    let runner = {
        let done_flag = Arc::clone(&done_flag);

        move || {
            log::debug!("Auto-confirmer thread started");

            // Note: `true` means that the communication will be done via "DebugLink";
            // it's completely independent from the normal communication that happens in the test.
            let device = find_test_device(true);
            let mut transport = trezor_client::transport::connect(&device).unwrap();

            while !done_flag.load() {
                log::trace!("Sending DebugLinkGetState");

                // Note: for some reason, passing `DebugWaitType::CURRENT_LAYOUT` may produce `MessageType_Failure`
                // in response (in particular, this happens at the start of the `sign_message` test), even though it's
                // supposed to wait for the next layout to appear. `IMMEDIATE` just returns an empty layout in this case.
                send_message(transport.as_mut(), {
                    // Note: here and below we don't use the "DebugLinkGetState { .. }" syntax to avoid direct dependency
                    // on the protobuf crate.
                    let mut msg = DebugLinkGetState::new();
                    msg.set_wait_layout(DebugWaitType::IMMEDIATE);
                    msg
                });

                log::trace!("DebugLinkGetState sent, expecting DebugLinkState as a response");

                let resp =
                    get_response::<trezor_client::protos::DebugLinkState>(transport.as_mut());

                // Note: when concatenated, `tokens` form a json string, e.g. for the home screen in may look like this:
                //    {"component": "Homescreen", "label": "Emulator"}
                // and one of our layouts may look like this:
                //    {
                //      "component": "Frame",
                //      "content": {
                //        "active_page": 0,
                //        "component": "ButtonPage",
                //        "content": { "component": "Paragraphs", "paragraphs": [["hex(93d344)"]] },
                //        "hold": true,
                //        "page_count": 1
                //      },
                //      "title": { "component": "Label", "text": "Confirm message" }
                //    }
                // The precise structure depends on the device/emulator being used.
                let tokens = resp.tokens.concat();
                // Note: the returned "json" may contain control characters, in which case it will
                // be rejected by serde; in particular, this happens in the sign_message test.
                // The reason is that our implementation of `sign_message` in trezor-firmware
                // tries (via `decode_message`) to interpret the passed message as a unicode string
                // and, if that succeeds, shows the string on the screen instead of the hexified
                // bytes. And whatever is shown on the screen is collected by `JsonTracer` without
                // any escaping. So we have to escape it here.
                // TODO: we should probably improve `decode_message` in the firmware, so that
                // the message is only interpreted as a string if it only contains printable chars
                // (or perhaps it should just escape non-printable chars itself).
                let tokens = escape_control_chars_in_tokens(&tokens);
                log::trace!("Got DebugLinkState, tokens = `{tokens}`");

                if !tokens.is_empty() {
                    let json_value = serde_json::from_str::<serde_json::Value>(&tokens).unwrap();
                    let obj = json_value.as_object().unwrap();

                    if obj.get("component").is_none_or(|v| v.as_str().unwrap() == "Homescreen") {
                        sleep(Duration::from_millis(200));
                    } else {
                        log::trace!("Sending DebugLinkDecision");

                        // Note:
                        // 1) According to a comment in `messages-debug.proto` in trezor-firmware,
                        // sending `DebugLinkDecision` should produce `DebugLinkLayout` as a response.
                        // However in reality it doesn't.
                        // 2) As mentioned in the docs (https://docs.trezor.io/trezor-firmware/core/misc/layout-lifecycle.html?highlight=DebugLinkDecision#synchronizing),
                        // `DebugLinkDecision` is also a synchronization event, so the next `DebugLinkGetState` that we send
                        // is guaranteed to return the layout that is the result of the decision.
                        send_message(transport.as_mut(), {
                            let mut msg = DebugLinkDecision::new();
                            msg.set_button(DebugButton::YES);
                            msg
                        });
                    }
                }
            }

            log::debug!("Auto-confirmer thread stopped");
        }
    };

    let join_handle = spawn_thread_aborting_on_panic(runner);

    Some(AutoConfirmerJoinHandle::new(join_handle, done_flag))
}

pub struct AutoConfirmerJoinHandle {
    // Note: Option is only needed to be able to join the handle on drop.
    join_handle: Option<JoinHandle<()>>,
    done_flag: Arc<RelaxedAtomicBool>,
}

impl AutoConfirmerJoinHandle {
    fn new(join_handle: JoinHandle<()>, done_flag: Arc<RelaxedAtomicBool>) -> Self {
        Self {
            join_handle: Some(join_handle),
            done_flag,
        }
    }

    #[allow(unused)]
    pub fn join(mut self) {
        self.join_impl();
    }

    fn join_impl(&mut self) {
        self.done_flag.store(true);
        self.join_handle.take().unwrap().join().unwrap();
        log::debug!("Auto-confirmer thread joined");
    }
}

impl Drop for AutoConfirmerJoinHandle {
    fn drop(&mut self) {
        self.join_impl();
    }
}

fn escape_control_chars_in_tokens(tokens: &str) -> String {
    let mut result = String::new();

    for ch in tokens.chars() {
        let cp = ch as u32;

        if cp < 0x20 {
            write!(&mut result, r#"\u{cp:04x}"#).unwrap();
        } else {
            result.push(ch);
        }
    }

    result
}
