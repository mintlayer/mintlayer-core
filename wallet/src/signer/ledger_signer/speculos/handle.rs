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

//! Speculos runtime handle, provides out-of-band interaction with a simulator instance
//! via the
//! [HTTP API](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/LedgerHQ/speculos/master/speculos/api/static/swagger/swagger.json)
//! to allow button pushes and screenshots when executing integration tests.
//!
//!

use std::net::SocketAddr;

use async_trait::async_trait;
use logging::log;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter};

/// Button enumeration
#[derive(Clone, Copy, PartialEq, Debug, Display, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum Button {
    Left,
    Right,
    Both,
}

/// Button actions
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize, Display, EnumIter)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    Press,
    Release,
    PressAndRelease,
}

/// Button action object for serialization and use with the HTTP API
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
struct ButtonAction {
    action: Action,
}

/// [Handle] trait for interacting with speculos
#[async_trait]
pub trait Handle {
    /// Get speculos HTTP address
    fn addr(&self) -> SocketAddr;

    /// Send a button action to the simulator
    async fn button(&self, button: Button, action: Action) -> anyhow::Result<()> {
        log::debug!("Sending button request: {}:{}", button, action);

        // Post action to HTTP API
        let r = Client::new()
            .post(format!("http://{}/button/{}", self.addr(), button))
            .json(&ButtonAction { action })
            .send()
            .await?;

        log::debug!("Button request complete: {}", r.status());

        Ok(())
    }
}

/// Handle to a Speculos instance running under Podman
#[derive(Debug)]
pub struct PodmanHandle {
    addr: SocketAddr,
}

impl PodmanHandle {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }
}

#[async_trait]
impl Handle for PodmanHandle {
    fn addr(&self) -> SocketAddr {
        self.addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    /// Check button string encoding
    #[test]
    fn button_encoding() {
        for button in Button::iter() {
            let expected = match button {
                Button::Left => "left",
                Button::Right => "right",
                Button::Both => "both",
            };
            assert_eq!(&button.to_string(), expected);
        }
    }

    /// Check button action encoding
    #[test]
    fn action_encoding() {
        for action in Action::iter() {
            let expected = match action {
                Action::Press => r#"{"action":"press"}"#,
                Action::Release => r#"{"action":"release"}"#,
                Action::PressAndRelease => r#"{"action":"press-and-release"}"#,
            };
            assert_eq!(
                &serde_json::to_string(&ButtonAction { action }).unwrap(),
                expected
            );
        }
    }
}
