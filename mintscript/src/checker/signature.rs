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

use common::chain::{
    signature::{
        sighash::input_commitments::SighashInputCommitment, DestinationSigError,
        EvaluatedInputWitness, Transactable,
    },
    ChainConfig, Destination,
};

pub trait SignatureChecker<C> {
    type Error: std::error::Error;

    /// Check signature
    fn check_signature(
        &mut self,
        ctx: &mut C,
        destination: &Destination,
        witness: &EvaluatedInputWitness,
    ) -> Result<(), Self::Error>;
}

/// Signature checker that does not check signatures. Useful if only timelock checks are requested.
pub struct NoOpSignatureChecker;

impl<C> SignatureChecker<C> for NoOpSignatureChecker {
    type Error = std::convert::Infallible;

    fn check_signature(
        &mut self,
        _ctx: &mut C,
        _dest: &Destination,
        _witness: &EvaluatedInputWitness,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub trait SignatureContext {
    type Tx: Transactable;

    /// Get chain config
    fn chain_config(&self) -> &ChainConfig;

    /// Get the transaction being signed
    fn transaction(&self) -> &Self::Tx;

    /// Get the list of input commitments
    fn input_commitments(&self) -> &[SighashInputCommitment<'_>];

    /// Get the input number
    fn input_num(&self) -> usize;
}

/// Signature checker that verifies signatures on basis of data provided by context.
pub struct StandardSignatureChecker;

impl<C: SignatureContext> SignatureChecker<C> for StandardSignatureChecker {
    type Error = DestinationSigError;

    fn check_signature(
        &mut self,
        ctx: &mut C,
        destination: &Destination,
        witness: &EvaluatedInputWitness,
    ) -> Result<(), Self::Error> {
        let tx = ctx.transaction();
        let input_num = ctx.input_num();
        let chain_config = ctx.chain_config();

        common::chain::signature::verify_signature(
            chain_config,
            destination,
            tx,
            witness,
            ctx.input_commitments(),
            input_num,
        )
    }
}
