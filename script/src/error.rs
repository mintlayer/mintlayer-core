// Copyright (c) 2021-2022 RBB S.r.l
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

//! Listing of all the error states

/// Ways that a script might fail. Not everything is split up as
/// much as it could be; patches welcome if more detailed errors
/// would help you.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy, thiserror::Error)]
pub enum Error {
    #[error("Something did a non-minimal push")]
    NonMinimalPush,
    #[error("Some opcode expected a parameter, but it was missing or truncated")]
    EarlyEndOfScript,
    #[error("Tried to read an array off the stack as a number when it was more than 4 bytes")]
    NumericOverflow,
    #[error("Illegal instruction executed")]
    IllegalOp,
    #[error("Syntactically incorrect OP_(NOT)IF/OP_ELSE/OP_ENDIF")]
    UnbalancedIfElse,
    #[error("Stack has insufficient number of elements in it")]
    NotEnoughElementsOnStack,
    #[error("Invalid operand to a script operation.")]
    InvalidOperand,
    #[error("OP_*VERIFY failed verification or OP_RETURN was executed.")]
    VerifyFail,
    #[error("Stack not clean after a script run.")]
    StackNotClean,
    #[error("Signature is not in correct format.")]
    SignatureFormat,
    #[error("Pubkey is not in correct format.")]
    PubkeyFormat,
    #[error("Push data too large.")]
    PushSize,
    #[error("Non-push operation present in context where only data push opcodes are allowed.")]
    PushOnly,
    #[error("Maximum stack size exceeded.")]
    StackSize,
    #[error("Maximum script size exceeded.")]
    ScriptSize,
    #[error("Incorrect number of public keys for multisig")]
    PubkeyCount,
    #[error("Incorrect number of signatures for multisig")]
    SigCount,
    #[error("Time lock interval not elapsed yet")]
    TimeLock,
    #[error("Multisig lacks extra 0 dummy.")]
    NullDummy,
}

pub type Result<T> = core::result::Result<T, Error>;
