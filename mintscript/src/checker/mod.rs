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

mod hashlock;
mod signature;
mod timelock;

use common::chain::{signature::EvaluatedInputWitness, timelock::OutputTimeLock, Destination};

pub use hashlock::HashlockError;
use hashlock::{HashlockChecker, NoOpHashlockChecker, StandardHashlockChecker};
pub use signature::{
    NoOpSignatureChecker, SignatureChecker, SignatureContext, StandardSignatureChecker,
};
use timelock::NoOpTimelockChecker;
pub use timelock::{StandardTimelockChecker, TimelockChecker, TimelockContext, TimelockError};

/// Script signature and timelock checker.
///
/// This contains a signature checker and timelock checker which can vary independently.
/// There is also shared context which both checkers have access to.
#[derive(Debug)]
pub struct ScriptChecker<C, S, T, H> {
    context: C,
    signature_checker: S,
    timelock_checker: T,
    hashlock_checker: H,
}

/// Script checker only verifying timelocks.
pub type TimelockOnlyScriptChecker<C> =
    ScriptChecker<C, NoOpSignatureChecker, StandardTimelockChecker, NoOpHashlockChecker>;

/// Script checker only verifying signatures.
pub type SignatureOnlyScriptChecker<C> =
    ScriptChecker<C, StandardSignatureChecker, NoOpTimelockChecker, NoOpHashlockChecker>;

/// Full script checker with all checks active.
pub type FullScriptChecker<C> =
    ScriptChecker<C, StandardSignatureChecker, StandardTimelockChecker, StandardHashlockChecker>;

impl<C> TimelockOnlyScriptChecker<C> {
    /// Create a script checker that only checks timelocks. Signatures are presumed to pass.
    pub fn timelock_only(context: C) -> Self {
        Self::custom(
            context,
            NoOpSignatureChecker,
            StandardTimelockChecker,
            NoOpHashlockChecker,
        )
    }
}

impl<C> SignatureOnlyScriptChecker<C> {
    /// Create a script checker that only checks signatures.
    pub fn signature_only(context: C) -> Self {
        Self::custom(
            context,
            StandardSignatureChecker,
            NoOpTimelockChecker,
            NoOpHashlockChecker,
        )
    }
}

impl<C> FullScriptChecker<C> {
    /// Create a full script checker verifying everything.
    pub fn full(context: C) -> Self {
        Self::custom(
            context,
            StandardSignatureChecker,
            StandardTimelockChecker,
            StandardHashlockChecker,
        )
    }
}

impl<C, S, T, H> ScriptChecker<C, S, T, H> {
    /// Create a script checker with custom checkers for signatures and timelocks.
    pub fn custom(
        context: C,
        signature_checker: S,
        timelock_checker: T,
        hashlock_checker: H,
    ) -> Self {
        Self {
            context,
            signature_checker,
            timelock_checker,
            hashlock_checker,
        }
    }

    pub fn into_components(self) -> (C, S, T, H) {
        (
            self.context,
            self.signature_checker,
            self.timelock_checker,
            self.hashlock_checker,
        )
    }

    pub fn into_context(self) -> C {
        self.context
    }
}

impl<C, S, T, H> crate::script::ScriptVisitor for ScriptChecker<C, S, T, H>
where
    S: SignatureChecker<C>,
    T: TimelockChecker<C>,
    H: HashlockChecker,
{
    type SignatureError = S::Error;
    type TimelockError = T::Error;
    type HashlockError = H::Error;

    fn visit_signature(
        &mut self,
        destination: &Destination,
        witness: &EvaluatedInputWitness,
    ) -> Result<(), Self::SignatureError> {
        self.signature_checker.check_signature(&mut self.context, destination, witness)
    }

    fn visit_timelock(&mut self, timelock: &OutputTimeLock) -> Result<(), Self::TimelockError> {
        self.timelock_checker.check_timelock(&mut self.context, timelock)
    }

    fn visit_hashlock(
        &mut self,
        hash_challenge: &crate::script::HashChallenge,
        preimage: &[u8; 32],
    ) -> Result<(), Self::HashlockError> {
        self.hashlock_checker.check_hashlock(hash_challenge, preimage)
    }
}
