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

//! Rust wrapper for executing Speculos via podman,
//! provided to simplify CI/CD with ledger applications.

use strum::{Display, EnumString, VariantNames};

mod drivers;
pub use drivers::*;

mod handle;
pub use handle::*;

/// Device model
#[derive(Copy, Clone, PartialEq, Debug, VariantNames, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum Model {
    /// Nano S
    NanoS,
    /// Nano S Plus
    #[strum(serialize = "nanosplus", to_string = "nanosp")]
    NanoSP,
    /// Nano X
    NanoX,
}

/// Simulator display mode
#[derive(Copy, Clone, PartialEq, Debug, VariantNames, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum Display {
    /// Headless mode
    Headless,
    /// QT based rendering
    Qt,
    /// Text based (command line) rendering
    Text,
}

/// Simulator options
#[derive(Clone, PartialEq, Debug)]
pub struct Options {
    /// Model to simulate
    pub model: Model,

    /// Display mode
    pub display: Display,

    /// SDK version override (defaults based on --model)
    pub sdk: Option<String>,

    /// API level override
    pub api_level: Option<String>,

    /// BIP39 seed for initialisation
    pub seed: Option<String>,

    /// Enable HTTP API port
    pub http_port: u16,

    /// Enable APDU TCP port (usually 1237)
    pub apdu_port: Option<u16>,

    /// Enable debugging and wait for GDB connection (port 1234)
    pub debug: bool,

    /// Speculos root (used to configure python paths if set)
    pub root: Option<String>,

    /// Trace syscalls
    pub trace: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            model: Model::NanoSP,
            display: Display::Headless,
            sdk: None,
            api_level: None,
            seed: None,
            http_port: 5000,
            apdu_port: None,
            debug: false,
            root: None,
            trace: false,
        }
    }
}

impl Options {
    /// Build an argument list from [Options]
    pub fn args(&self) -> Vec<String> {
        // Basic args
        let mut args = vec![
            format!("--model={}", self.model),
            format!("--display={}", self.display),
            format!("--api-port={}", self.http_port),
        ];

        if let Some(seed) = &self.seed {
            args.push(format!("--seed={seed}"));
        }

        if let Some(apdu_port) = &self.apdu_port {
            args.push(format!("--apdu-port={apdu_port}"));
        }

        if let Some(sdk) = &self.sdk {
            args.push(format!("--sdk={sdk}"));
        }

        if let Some(api_level) = &self.api_level {
            args.push(format!("--apiLevel={api_level}"));
        }

        if self.debug {
            args.push("--debug".to_string());
        }

        if self.trace {
            args.push("-t".to_string());
        }

        args
    }
}
