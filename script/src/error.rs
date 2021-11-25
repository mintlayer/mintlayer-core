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

//! Listing of all the error states

use displaydoc::Display;

/// Ways that a script might fail. Not everything is split up as
/// much as it could be; patches welcome if more detailed errors
/// would help you.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy, Display)]
pub enum Error {
    /// Something did a non-minimal push
    NonMinimalPush,
    /// Some opcode expected a parameter, but it was missing or truncated
    EarlyEndOfScript,
    /// Tried to read an array off the stack as a number when it was more than 4 bytes
    NumericOverflow,
    /// Illegal instruction executed
    IllegalOp,
    /// Syntactically incorrect OP_(NOT)IF/OP_ELSE/OP_ENDIF
    UnbalancedIfElse,
    /// Stack has insufficient number of elements in it
    NotEnoughElementsOnStack,
    /// Invalid operand to a script operation.
    InvalidOperand,
    /// OP_*VERIFY failed verification or OP_RETURN was executed.
    VerifyFail,
    /// Stack not clean after a script run.
    StackNotClean,
    /// Signature is not in correct format.
    SignatureFormat,
    /// Pubkey is not in correct format.
    PubkeyFormat,
    /// Push data too large.
    PushSize,
    /// Non-push operation present in context where only data push opcodes are allowed.
    PushOnly,
    /// Maximum stack size exceeded.
    StackSize,
    /// Maximum script size exceeded.
    ScriptSize,
    /// Incorrect number of public keys for multisig
    PubkeyCount,
    /// Incorrect number of signatures for multisig
    SigCount,
    /// Time lock interval not elapsed yet
    TimeLock,
    /// Multisig lacks extra 0 dummy.
    NullDummy,
}

impl ::std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
