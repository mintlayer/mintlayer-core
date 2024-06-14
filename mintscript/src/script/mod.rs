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

mod display;
mod verify;

use common::chain::{signature::inputsig::InputWitness, timelock::OutputTimeLock, Destination};
use utils::ensure;

pub use verify::{ScriptError, ScriptErrorOf, ScriptResult, ScriptVisitor};

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ScriptConstructionError {
    #[error("Threshold requires {0} conditions but contains only {1}")]
    InvalidThreshold(usize, usize),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Threshold {
    required: usize,
    conditions: Vec<ScriptCondition>,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum ThresholdError {
    #[error("Not enough conditions satisfied")]
    Insufficient,

    #[error("Too many conditions declared satisfied")]
    Excessive,
}

impl Threshold {
    /// Trivially satisfied threshold condition (represented as 0-of-0 threshold)
    pub const TRUE: Self = Self::new_unchecked(0, Vec::new());

    /// Construct a threshold.
    const fn new_unchecked(required: usize, conditions: Vec<ScriptCondition>) -> Self {
        Self {
            required,
            conditions,
        }
    }

    /// Construct a threshold.
    ///
    /// Creates an N-of-K threshold construct where N out of K conditions have to be satisfied.
    /// Fails if N > K.
    pub fn new(
        required: usize,
        conditions: Vec<ScriptCondition>,
    ) -> Result<Self, ScriptConstructionError> {
        ensure!(
            required <= conditions.len(),
            ScriptConstructionError::InvalidThreshold(required, conditions.len()),
        );
        Ok(Self::new_unchecked(required, conditions))
    }

    /// A [WitnessScript] consisting of only this threshold.
    pub const fn into_script(self) -> WitnessScript {
        WitnessScript::Threshold(self)
    }

    /// Get all the conditions in this threshold construct.
    pub fn conditions(&self) -> &[ScriptCondition] {
        &self.conditions
    }

    /// Number of conditions that need to be satisfied in order for the threshold to be valid.
    pub fn required(&self) -> usize {
        self.required
    }

    /// Number of conditions that need to be dissatisfied in order for the threshold to be valid.
    pub fn required_dissat(&self) -> usize {
        let num_conds = self.conditions().len();
        num_conds.checked_sub(self.required()).expect("checked during construction")
    }

    /// Collect conditions that the prover claims to satisfy.
    pub fn collect_satisfied_unchecked(&self) -> Vec<&WitnessScript> {
        self.conditions.iter().filter_map(ScriptCondition::as_satisfied).collect()
    }

    /// Collect conditions that the prover claims to satisfy and check the number of these meets
    /// the threshold requirements.
    pub fn collect_satisfied(&self) -> Result<Vec<&WitnessScript>, ThresholdError> {
        // Track how many conditions are there to be left satisfied and dissatisfied
        let mut left_sat = self.required();
        let mut left_dissat = self.required_dissat();
        let mut satisfied = Vec::with_capacity(left_sat);

        for cond in self.conditions() {
            match cond {
                ScriptCondition::Satisfied(ws) => {
                    left_sat = left_sat.checked_sub(1).ok_or(ThresholdError::Excessive)?;
                    satisfied.push(ws);
                }
                ScriptCondition::Dissatisfied(_) => {
                    left_dissat = left_dissat.checked_sub(1).ok_or(ThresholdError::Insufficient)?;
                }
            }
        }

        assert_eq!(left_dissat, 0);
        assert_eq!(left_sat, 0);

        Ok(satisfied)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HashChallenge {
    Ripemd160([u8; 20]),
    Sha1([u8; 20]),
    Sha256([u8; 32]),
    Hash160([u8; 20]),
    Hash256([u8; 32]),
}

/// Script together with witness data presumably satisfying the script.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum WitnessScript {
    Threshold(Threshold),
    Signature(Destination, InputWitness),
    Timelock(OutputTimeLock),
    HashLock {
        hash_challenge: HashChallenge,
        preimage: [u8; 32],
    },
}

impl WitnessScript {
    /// Trivially satisfied script (represented as 0-of-0 threshold)
    pub const TRUE: Self = Threshold::TRUE.into_script();

    /// Construct a public key / signature lock
    pub const fn signature(dest: Destination, sig: InputWitness) -> Self {
        Self::Signature(dest, sig)
    }

    /// Construct a timelock condition
    pub const fn timelock(tl: OutputTimeLock) -> Self {
        Self::Timelock(tl)
    }

    /// Construct a hashlock condition
    pub const fn hashlock(hash_challenge: HashChallenge, preimage: [u8; 32]) -> Self {
        Self::HashLock {
            hash_challenge,
            preimage,
        }
    }

    /// Construct a threshold. See [Threshold::new_unchecked].
    fn threshold_unchecked(required: usize, conds: Vec<ScriptCondition>) -> Self {
        assert!(required <= conds.len());
        Threshold::new_unchecked(required, conds).into_script()
    }

    /// Construct a threshold. See [Threshold::new].
    pub fn threshold(
        required: usize,
        conds: Vec<ScriptCondition>,
    ) -> Result<Self, ScriptConstructionError> {
        Threshold::new(required, conds).map(Threshold::into_script)
    }

    /// Construct a disjunction of multiple conditions.
    pub fn disjunction(conds: Vec<ScriptCondition>) -> Result<Self, ScriptConstructionError> {
        Self::threshold(1, conds)
    }

    /// Construct a conjunction of multiple conditions.
    pub fn conjunction(conds: Vec<ScriptCondition>) -> Self {
        Self::threshold_unchecked(conds.len(), conds)
    }

    /// Construct a conjunction of multiple satisfied conditions.
    pub fn satisfied_conjunction(conds: impl IntoIterator<Item = WitnessScript>) -> Self {
        Self::conjunction(conds.into_iter().map(ScriptCondition::Satisfied).collect())
    }
}

/// A script portion the user chose to not satisfy.
///
/// This should eventually be turned into a spending condition commitment so we can verify the
/// condition is the same one as one agreed upon in the contract. Only needed if the script ends up
/// on chain which is a future development.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DissatisfiedScript {
    False,
}

/// A script that can be either satisfied or dissatisfied, as determined by the user.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ScriptCondition {
    Satisfied(WitnessScript),
    Dissatisfied(DissatisfiedScript),
}

impl ScriptCondition {
    /// Trivially dissatisfied script condition
    pub const FALSE: Self = Self::Dissatisfied(DissatisfiedScript::False);

    /// Trivially satisfied script condition
    pub const TRUE: Self = Self::Satisfied(WitnessScript::TRUE);

    /// Create a trivial script condition from a bool.
    pub const fn from_bool(b: bool) -> Self {
        match b {
            true => Self::TRUE,
            false => Self::FALSE,
        }
    }

    /// Get the satisfied script, if any.
    pub fn as_satisfied(&self) -> Option<&WitnessScript> {
        match self {
            Self::Satisfied(ws) => Some(ws),
            Self::Dissatisfied(_) => None,
        }
    }
}
