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
// Author(s): S. Afach & L. Kuklinek

use parity_scale_codec::Encode;

use super::TransactionSigError;

/// Specifies which parts of the transaction a signature commits to.
///
/// The values of the flags are the same as in Bitcoin.
#[derive(Eq, PartialEq, Clone, Copy, Encode, Debug, Ord, PartialOrd)]
pub struct SigHashType(u8);

impl SigHashType {
    pub const ALL: u8 = 0x01;
    pub const NONE: u8 = 0x02;
    pub const SINGLE: u8 = 0x03;
    pub const ANYONECANPAY: u8 = 0x80;

    const MASK_OUT: u8 = 0x7f;
    const MASK_IN: u8 = 0x80;

    pub fn inputs_mode(&self) -> InputsMode {
        match self.0 & Self::MASK_IN {
            Self::ANYONECANPAY => InputsMode::AnyoneCanPay,
            _ => InputsMode::CommitWhoPays,
        }
    }

    pub fn outputs_mode(&self) -> OutputsMode {
        match self.0 & Self::MASK_OUT {
            Self::NONE => OutputsMode::None,
            Self::SINGLE => OutputsMode::Single,
            _ => OutputsMode::All,
        }
    }

    pub fn get(&self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for SigHashType {
    type Error = TransactionSigError;

    fn try_from(sighash_byte: u8) -> Result<Self, Self::Error> {
        let ok = matches!(
            sighash_byte & Self::MASK_OUT,
            Self::ALL | Self::NONE | Self::SINGLE
        );
        ok.then(|| Self(sighash_byte))
            .ok_or(TransactionSigError::InvalidSigHashValue(sighash_byte))
    }
}

/// How inputs should be hashed
#[derive(PartialEq, Eq, Debug)]
pub enum InputsMode {
    /// Commit to all inputs
    CommitWhoPays,
    /// Commit to the current input only
    AnyoneCanPay,
}

impl Default for SigHashType {
    fn default() -> Self {
        Self(SigHashType::ALL)
    }
}

/// How outputs should be hashed
#[derive(PartialEq, Eq, Debug)]
pub enum OutputsMode {
    /// Commit to all outputs
    All,
    /// Don't commit to any outputs
    None,
    /// Commit to the output corresponding to the current input
    Single,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[allow(clippy::eq_op)]
    fn check_sighashtype_conversion() {
        // Check inputs and outputs mode
        let sighash_type = SigHashType::try_from(SigHashType::ALL).unwrap();
        assert_eq!(sighash_type.inputs_mode(), InputsMode::CommitWhoPays);
        assert_eq!(sighash_type.outputs_mode(), OutputsMode::All);

        let sighash_type =
            SigHashType::try_from(SigHashType::ALL | SigHashType::ANYONECANPAY).unwrap();
        assert_eq!(sighash_type.inputs_mode(), InputsMode::AnyoneCanPay);
        assert_eq!(sighash_type.outputs_mode(), OutputsMode::All);

        let sighash_type = SigHashType::try_from(SigHashType::NONE).unwrap();
        assert_eq!(sighash_type.inputs_mode(), InputsMode::CommitWhoPays);
        assert_eq!(sighash_type.outputs_mode(), OutputsMode::None);

        let sighash_type =
            SigHashType::try_from(SigHashType::NONE | SigHashType::ANYONECANPAY).unwrap();
        assert_eq!(sighash_type.inputs_mode(), InputsMode::AnyoneCanPay);
        assert_eq!(sighash_type.outputs_mode(), OutputsMode::None);

        let sighash_type = SigHashType::try_from(SigHashType::SINGLE).unwrap();
        assert_eq!(sighash_type.inputs_mode(), InputsMode::CommitWhoPays);
        assert_eq!(sighash_type.outputs_mode(), OutputsMode::Single);

        let sighash_type =
            SigHashType::try_from(SigHashType::SINGLE | SigHashType::ANYONECANPAY).unwrap();
        assert_eq!(sighash_type.inputs_mode(), InputsMode::AnyoneCanPay);
        assert_eq!(sighash_type.outputs_mode(), OutputsMode::Single);

        // Check try from
        assert_eq!(
            SigHashType::try_from(0),
            Err(TransactionSigError::InvalidSigHashValue(0))
        );
        assert_eq!(
            SigHashType::try_from(SigHashType::ANYONECANPAY),
            Err(TransactionSigError::InvalidSigHashValue(
                SigHashType::ANYONECANPAY
            ))
        );
    }
}
