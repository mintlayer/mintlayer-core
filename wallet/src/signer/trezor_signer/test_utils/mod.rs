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

mod auto_confirmer;

use itertools::Itertools as _;
use trezor_client::{find_devices, AvailableDevice, Model, Trezor, TrezorMessage};

use logging::log;
use utils::env_utils::bool_from_env;

pub use auto_confirmer::*;

pub fn should_use_real_device() -> bool {
    bool_from_env("TREZOR_TESTS_USE_REAL_DEVICE").unwrap().unwrap_or(false)
}

pub fn should_auto_confirm() -> bool {
    // Note: auto-confirm requires DebugLink to be enabled, which in turn requires the firmware
    // to be built with DEBUG_LINK=1. For the emulator this is true by default (set by `build_unix`),
    // but for a real device it will normally be false. So by default we enable auto-confirm for
    // the emulator and disable for real devices.
    let default = !should_use_real_device();
    bool_from_env("TREZOR_TESTS_AUTO_CONFIRM").unwrap().unwrap_or(default)
}

pub fn find_test_device_and_connect(debug: bool) -> Trezor {
    find_test_device(debug).connect().unwrap()
}

pub fn find_test_device(debug: bool) -> AvailableDevice {
    let use_real_device = should_use_real_device();

    let devices = find_devices(debug)
        .into_iter()
        .filter(|device| {
            if use_real_device {
                // Note: we don't support `Model::TrezorLegacy` AKA Trezor Model One.
                device.model == Model::Trezor
            } else {
                device.model == Model::TrezorEmulator
            }
        })
        .collect_vec();

    if devices.len() > 1 {
        log::warn!("More than one device found, using the first one in the list");
    }

    devices.into_iter().next().unwrap()
}

// Note: `trezor_client::Trezor` only exposes `call_raw`, in which `write_message` is always followed
// by `read_message`. Since we sometimes need to send messages that don't result in a response, we
// have to use the transport directly.
fn send_message<M: TrezorMessage>(transport: &mut dyn trezor_client::transport::Transport, msg: M) {
    let proto_msg =
        trezor_client::transport::ProtoMessage(M::MESSAGE_TYPE, msg.write_to_bytes().unwrap());
    transport.write_message(proto_msg).unwrap();
}

fn get_response<M: TrezorMessage>(transport: &mut dyn trezor_client::transport::Transport) -> M {
    let resp = transport.read_message().unwrap();

    if resp.message_type() == M::MESSAGE_TYPE {
        resp.into_message::<M>().unwrap()
    } else {
        panic!("Unexpected response type: {:?}", resp.message_type());
    }
}
