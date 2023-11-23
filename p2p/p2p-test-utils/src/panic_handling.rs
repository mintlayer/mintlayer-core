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

use once_cell::sync::Lazy;
use tokio::sync::Notify;

use logging::log;

static PANIC_NOTIFICATION: Lazy<Notify> = Lazy::new(Notify::new);

// If a panic occurs inside a thread or tokio task, the application won't be aborted until
// the corresponding handle is joined. On the other hand, in p2p tests we often wait for a
// future to complete using large timeouts; if a panic occurs during such wait, we'd want to
// abort it immediately rather than wait for the timeout to expire. This function can be used
// for this purpose.
pub async fn get_panic_notification() {
    PANIC_NOTIFICATION.notified().await
}

fn setup_panic_handling() {
    let old_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        log::error!("A panic occurred: {panic_info}");

        PANIC_NOTIFICATION.notify_one();
        old_panic_hook(panic_info);
    }));
}

#[ctor::ctor]
fn init() {
    setup_panic_handling();
}
