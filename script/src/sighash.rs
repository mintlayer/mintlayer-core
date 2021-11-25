// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): L. Kuklinek

/// Specifies which parts of the transaction a signature commits to.
///
/// The values of the flags are the same as in Bitcoin.
#[derive(Eq, PartialEq, Clone, Copy)]
pub struct SigHash(u8);

impl SigHash {
    const DEFAULT: u8 = 0x00;
    const ALL: u8 = 0x01;
    const NONE: u8 = 0x02;
    const SINGLE: u8 = 0x03;
    const ANYONECANPAY: u8 = 0x80;

    const MASK_OUT: u8 = 0x7f;
    const MASK_IN: u8 = 0x80;

    pub fn from_u8(sighash_byte: u8) -> Option<SigHash> {
        let ok = matches!(
            sighash_byte & Self::MASK_OUT,
            Self::ALL | Self::NONE | Self::SINGLE
        );
        ok.then(|| Self(sighash_byte))
    }

    pub fn input_mode(&self) -> InputMode {
        match self.0 & Self::MASK_IN {
            Self::ANYONECANPAY => InputMode::AnyoneCanPay,
            _ => InputMode::CommitWhoPays,
        }
    }

    pub fn output_mode(&self) -> OutputMode {
        match self.0 & Self::MASK_OUT {
            Self::NONE => OutputMode::None,
            Self::SINGLE => OutputMode::Single,
            _ => OutputMode::All,
        }
    }
}

impl Default for SigHash {
    fn default() -> Self {
        Self(Self::DEFAULT)
    }
}

/// How inputs should be hashed
pub enum InputMode {
    /// Commit to all inputs
    CommitWhoPays,
    /// Commit to the current input only
    AnyoneCanPay,
}

/// How outputs should be hashed
pub enum OutputMode {
    /// Commit to all outputs
    All,
    /// Don't commit to any outputs
    None,
    /// Commit to the output corresponding to the current input
    Single,
}
