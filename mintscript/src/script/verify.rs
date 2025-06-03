// Copyright (c) 2024 RBB S.r.l
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

//! Script verification / evaluation

use common::chain::{signature::EvaluatedInputWitness, timelock::OutputTimeLock, Destination};

use super::{HashChallenge, WitnessScript};

/// A script processing object
///
/// This object is used to handle "leaf" script constructs that require extra context not present
/// in the script itself to be fully processed. Namely:
///
/// * Verifying a signature requires the knowledge of the transaction contents so the signed
///   message can pe properly calculated.
/// * Verifying a timelock requires the information about block heights and timestamps.
///
/// In addition to that, it may provide extra information like fork feature activation flags and
/// similar bits of information in the future.
pub trait ScriptVisitor {
    type SignatureError: std::error::Error;
    type TimelockError: std::error::Error;
    type HashlockError: std::error::Error;

    /// Check signature
    fn visit_signature(
        &mut self,
        destination: &Destination,
        witness: &EvaluatedInputWitness,
    ) -> Result<(), Self::SignatureError>;

    /// Check timelock
    fn visit_timelock(&mut self, timelock: &OutputTimeLock) -> Result<(), Self::TimelockError>;

    /// Check hashlock
    fn visit_hashlock(
        &mut self,
        hash_challenge: &HashChallenge,
        preimage: &[u8; 32],
    ) -> Result<(), Self::HashlockError>;
}

/// Script verification error
#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum ScriptError<SE, TE, HE> {
    #[error(transparent)]
    Signature(SE),

    #[error(transparent)]
    Timelock(TE),

    #[error(transparent)]
    Hashlock(HE),

    #[error(transparent)]
    Threshold(#[from] super::ThresholdError),
}

impl<S0, T0, H0> ScriptError<S0, T0, H0> {
    /// Apply [Into::into] to both generic error fields.
    pub fn errs_into<S1: From<S0>, T1: From<T0>, H1: From<H0>>(self) -> ScriptError<S1, T1, H1> {
        match self {
            Self::Signature(e) => ScriptError::Signature(e.into()),
            Self::Timelock(e) => ScriptError::Timelock(e.into()),
            Self::Hashlock(e) => ScriptError::Hashlock(e.into()),
            Self::Threshold(e) => ScriptError::Threshold(e),
        }
    }
}

pub type ScriptErrorOf<V> = ScriptError<
    <V as ScriptVisitor>::SignatureError,
    <V as ScriptVisitor>::TimelockError,
    <V as ScriptVisitor>::HashlockError,
>;
pub type ScriptResult<T, V> = Result<T, ScriptErrorOf<V>>;

impl WitnessScript {
    /// Evaluate (verify) given script.
    ///
    /// Checking of signatures and time locks is delegated to the provided visitor object.
    pub fn verify<V: ScriptVisitor>(&self, v: &mut V) -> ScriptResult<(), V> {
        let mut eval_stack = vec![self];

        while let Some(expr) = eval_stack.pop() {
            match expr {
                Self::Signature(destination, signature) => {
                    v.visit_signature(destination, signature).map_err(ScriptError::Signature)?;
                }
                Self::Timelock(tl) => {
                    v.visit_timelock(tl).map_err(ScriptError::Timelock)?;
                }
                Self::Threshold(thresh) => {
                    eval_stack.extend(thresh.collect_satisfied()?.into_iter().rev());
                }
                Self::HashLock {
                    hash_challenge,
                    preimage,
                } => {
                    v.visit_hashlock(hash_challenge, preimage).map_err(ScriptError::Hashlock)?;
                }
            }
        }

        Ok(())
    }
}
