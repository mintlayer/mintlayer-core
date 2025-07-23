//! Speculos runtime handle, provides out-of-band interaction with a simulator instance
//! via the [HTTP API](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/LedgerHQ/speculos/master/speculos/api/static/swagger/swagger.json) to allow button pushes and screenshots when executing integration tests.
//!
//!

use std::net::SocketAddr;

use async_trait::async_trait;
// use image::{io::Reader as ImageReader, DynamicImage};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use strum::Display;
use tracing::debug;

use crate::signer::ledger_signer::speculus::GenericHandle;

// use crate::GenericHandle;

/// Button enumeration
#[derive(Clone, Copy, PartialEq, Debug, Display)]
#[strum(serialize_all = "kebab-case")]
pub enum Button {
    Left,
    Right,
    Both,
}

/// Button actions
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize, Display)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    Press,
    Release,
    PressAndRelease,
}

/// Button action object for serialisation and use with the HTTP API
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
struct ButtonAction {
    pub action: Action,
}

/// [Handle] trait for interacting with speculos
#[async_trait]
pub trait Handle {
    /// Get speculos HTTP address
    fn addr(&self) -> SocketAddr;

    /// Send a button action to the simulator
    async fn button(&self, button: Button, action: Action) -> anyhow::Result<()> {
        debug!("Sending button request: {}:{}", button, action);

        // Post action to HTTP API
        let r = Client::new()
            .post(format!("http://{}/button/{}", self.addr(), button))
            .json(&ButtonAction { action })
            .send()
            .await?;

        debug!("Button request complete: {}", r.status());

        Ok(())
    }

    // /// Fetch a screenshot from the simulator
    // async fn screenshot(&self) -> anyhow::Result<DynamicImage> {
    //     // Fetch screenshot from HTTP API
    //     let r = reqwest::get(format!("http://{}/screenshot", self.addr())).await?;
    //
    //     // Read image bytes
    //     let b = r.bytes().await?;
    //
    //     // Parse image object
    //     let i = ImageReader::new(Cursor::new(b)).with_guessed_format()?.decode()?;
    //
    //     Ok(i)
    // }
}

impl Handle for GenericHandle {
    fn addr(&self) -> SocketAddr {
        match self {
            GenericHandle::Local(h) => h.addr(),
            GenericHandle::Docker(h) => h.addr(),
            GenericHandle::Podman(h) => h.addr(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Check button string encoding
    #[test]
    fn button_encoding() {
        let tests = &[(Button::Left, "left"), (Button::Right, "right"), (Button::Both, "both")];

        for (v, s) in tests {
            assert_eq!(&v.to_string(), s);
        }
    }

    /// Check button action encoding
    #[test]
    fn action_encoding() {
        let tests = &[
            (
                ButtonAction {
                    action: Action::Press,
                },
                r#"{"action":"press"}"#,
            ),
            (
                ButtonAction {
                    action: Action::Release,
                },
                r#"{"action":"release"}"#,
            ),
            (
                ButtonAction {
                    action: Action::PressAndRelease,
                },
                r#"{"action":"press-and-release"}"#,
            ),
        ];

        for (v, s) in tests {
            assert_eq!(&serde_json::to_string(v).unwrap(), s);
        }
    }
}
