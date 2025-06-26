// Copyright (c) 2021-2025 RBB S.r.l
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
    block::BlockRewardTransactable,
    signature::{
        sighash::input_commitments::{
            make_sighash_input_commitments_for_kernel_inputs,
            make_sighash_input_commitments_for_transaction_inputs, SighashInputCommitment,
        },
        Signable,
    },
    SignedTransaction,
};

use super::{CoreContext, InputCheckError};

pub trait SighashInputCommitmentsSource {
    fn get_input_commitments<'a>(
        &self,
        core_ctx: &'a CoreContext,
    ) -> Result<Vec<SighashInputCommitment<'a>>, InputCheckError>;
}

impl SighashInputCommitmentsSource for SignedTransaction {
    fn get_input_commitments<'a>(
        &self,
        core_ctx: &'a CoreContext,
    ) -> Result<Vec<SighashInputCommitment<'a>>, InputCheckError> {
        Ok(make_sighash_input_commitments_for_transaction_inputs(
            self.inputs(),
            &core_ctx,
        )?)
    }
}

impl SighashInputCommitmentsSource for BlockRewardTransactable<'_> {
    fn get_input_commitments<'a>(
        &self,
        core_ctx: &'a CoreContext,
    ) -> Result<Vec<SighashInputCommitment<'a>>, InputCheckError> {
        if let Some(kernel_inputs) = self.inputs() {
            let commitments =
                make_sighash_input_commitments_for_kernel_inputs(kernel_inputs, &core_ctx)?;

            Ok(commitments)
        } else {
            Ok(Vec::new())
        }
    }
}
