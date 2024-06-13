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

mod signature;
mod timelock;

use common::chain::{signature::inputsig::InputWitness, timelock::OutputTimeLock, Destination};

pub use signature::{
    NoOpSignatureChecker, SignatureChecker, SignatureContext, StandardSignatureChecker,
};
pub use timelock::{StandardTimelockChecker, TimelockChecker, TimelockContext, TimelockError};

/// Script signature and timelock checker.
///
/// This contains a signature checker and timelock checker which can vary independently.
/// There is also shared context which both checkers have access to.
#[derive(Debug)]
pub struct ScriptChecker<C, S, T> {
    context: C,
    signature_checker: S,
    timelock_checker: T,
}

/// Script checker only verifying timelocks.
pub type TimelockOnlyScriptChecker<C> =
    ScriptChecker<C, NoOpSignatureChecker, StandardTimelockChecker>;

/// Full script checker with all checks active.
pub type FullScriptChecker<C> = ScriptChecker<C, StandardSignatureChecker, StandardTimelockChecker>;

impl<C> TimelockOnlyScriptChecker<C> {
    /// Create a script checker that only checks timelocks. Signatures are presumed to pass.
    pub fn timelock_only(context: C) -> Self {
        Self::custom(context, NoOpSignatureChecker, StandardTimelockChecker)
    }
}

impl<C> FullScriptChecker<C> {
    /// Create a full script checker verifying everything.
    pub fn full(context: C) -> Self {
        Self::custom(context, StandardSignatureChecker, StandardTimelockChecker)
    }
}

impl<C, S, T> ScriptChecker<C, S, T> {
    /// Create a script checker with custom checkers for signatures and timelocks.
    pub fn custom(context: C, signature_checker: S, timelock_checker: T) -> Self {
        Self {
            context,
            signature_checker,
            timelock_checker,
        }
    }

    pub fn into_components(self) -> (C, S, T) {
        (self.context, self.signature_checker, self.timelock_checker)
    }

    pub fn into_context(self) -> C {
        self.context
    }
}

impl<C, S, T> crate::script::ScriptVisitor for ScriptChecker<C, S, T>
where
    S: SignatureChecker<C>,
    T: TimelockChecker<C>,
{
    type SignatureError = S::Error;

    type TimelockError = T::Error;

    fn visit_signature(
        &mut self,
        destination: &Destination,
        signature: &InputWitness,
    ) -> Result<(), Self::SignatureError> {
        self.signature_checker
            .check_signature(&mut self.context, destination, signature)
    }

    fn visit_timelock(&mut self, timelock: &OutputTimeLock) -> Result<(), Self::TimelockError> {
        self.timelock_checker.check_timelock(&mut self.context, timelock)
    }
}
