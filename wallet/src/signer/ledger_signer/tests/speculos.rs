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

use std::{net::SocketAddr, time::Duration};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter};
use tokio::time::sleep;

use logging::log;

/// Device types supported by the emulator
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Device {
    NanoS,
    NanoSPlus,
    NanoX,
    Stax,
    Flex,
    NanoGen5,
}

impl Device {
    /// Returns true if the device has a touch screen
    pub fn is_touch(&self) -> bool {
        matches!(self, Device::Stax | Device::Flex | Device::NanoGen5)
    }
}

/// Button enumeration (Physical buttons)
#[derive(Clone, Copy, PartialEq, Debug, Display, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum Button {
    Left,
    Right,
    Both,
}

/// Physical Button actions
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize, Display, EnumIter)]
#[serde(rename_all = "kebab-case")]
pub enum ButtonAction {
    Press,
    Release,
    PressAndRelease,
}

/// Payload for button endpoint
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
struct ButtonPayload {
    action: ButtonAction,
}

// -----------------------------------------------------------------
// TOUCH SCREEN LOGIC
// -----------------------------------------------------------------

/// Payload for the /finger endpoint
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub struct FingerPayload {
    pub x: u32,
    pub y: u32,
    pub action: ButtonAction,
    // delay is optional in speculos, usually 0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay: Option<u32>,
}

/// Semantic elements on the screen to avoid hardcoding X/Y in tests.
/// Mapped from the "UseCase" python dictionary.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ScreenElement {
    ReviewTap,     // Used to go to next page (lower right)
    ReviewConfirm, // Above lower right
}

impl ScreenElement {
    /// Returns the (x, y) coordinates for the specific device
    pub fn position(&self, device: Device) -> (u32, u32) {
        // Device resolutions
        // Stax: 400 x 672
        // Flex: 480 x 600
        match (self, device) {
            // --- UseCaseReview ---
            (ScreenElement::ReviewTap, Device::Stax) => (335, 606),
            (ScreenElement::ReviewTap, Device::Flex) => (430, 530),
            (ScreenElement::ReviewTap, Device::NanoGen5) => (295, 370),

            (ScreenElement::ReviewConfirm, Device::Stax) => (335, 515),
            (ScreenElement::ReviewConfirm, Device::Flex) => (240, 435),
            (ScreenElement::ReviewConfirm, Device::NanoGen5) => (290, 335),

            // Fallback or unimplemented combinations
            _ => panic!("Coordinate not mapped for {:?} on {:?}", self, device),
        }
    }
}

// -----------------------------------------------------------------
// RUNTIME HANDLE
// -----------------------------------------------------------------

/// Handle for interacting with a Speculos instance
#[derive(Debug, Clone)]
pub struct Handle {
    addr: SocketAddr,
    device: Device,
}

impl Handle {
    pub fn new(addr: SocketAddr, device: Device) -> Self {
        Self { addr, device }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn device(&self) -> Device {
        self.device
    }

    /// Send a physical button action
    pub async fn button(&self, button: Button, action: ButtonAction) -> anyhow::Result<()> {
        if self.device.is_touch() {
            log::warn!(concat!(
                "Sending physical button command to a touch device (Stax/Flex).",
                "This might be intended (Power button) but usually incorrect for UI navigation."
            ));
        }

        log::debug!("Sending button request: {}:{}", button, action);

        let r = Client::new()
            .post(format!("http://{}/button/{}", self.addr(), button))
            .json(&ButtonPayload { action })
            .send()
            .await?;

        if !r.status().is_success() {
            anyhow::bail!("Button request failed: {}", r.status());
        }

        Ok(())
    }

    /// Send a raw finger action to the screen
    pub async fn finger(&self, x: u32, y: u32, action: ButtonAction) -> anyhow::Result<()> {
        log::debug!("Sending finger request: x={} y={} action={}", x, y, action);

        let payload = FingerPayload {
            x,
            y,
            action,
            delay: None,
        };

        let r = Client::new()
            .post(format!("http://{}/finger", self.addr()))
            .json(&payload)
            .send()
            .await?;

        if !r.status().is_success() {
            anyhow::bail!("Finger request failed: {}", r.status());
        }

        Ok(())
    }

    pub async fn hold(&self, element: ScreenElement) -> anyhow::Result<()> {
        let (x, y) = element.position(self.device);
        self.finger(x, y, ButtonAction::Press).await?;
        sleep(Duration::from_millis(1800)).await;
        self.finger(x, y, ButtonAction::Release).await?;
        Ok(())
    }

    pub async fn tap(&self, element: ScreenElement) -> anyhow::Result<()> {
        let (x, y) = element.position(self.device);
        self.finger(x, y, ButtonAction::PressAndRelease).await?;
        Ok(())
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
        for action in ButtonAction::iter() {
            let expected = match action {
                ButtonAction::Press => r#"{"action":"press"}"#,
                ButtonAction::Release => r#"{"action":"release"}"#,
                ButtonAction::PressAndRelease => r#"{"action":"press-and-release"}"#,
            };
            assert_eq!(
                &serde_json::to_string(&ButtonPayload { action }).unwrap(),
                expected
            );
        }
    }
}
