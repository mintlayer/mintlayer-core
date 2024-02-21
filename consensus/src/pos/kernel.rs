// Copyright (c) 2023 RBB S.r.l
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

use common::chain::{TxInput, TxOutput};
use utxo::UtxosView;

use crate::pos::error::ConsensusPoSError;

pub fn get_kernel_output<U: UtxosView>(
    kernel_inputs: &[TxInput],
    utxos_view: &U,
) -> Result<TxOutput, ConsensusPoSError> {
    match kernel_inputs {
        [] => Err(ConsensusPoSError::NoKernel),
        [kernel_input] => {
            let kernel_outpoint = kernel_input
                .utxo_outpoint()
                .ok_or(ConsensusPoSError::KernelOutpointMustBeUtxo)?;
            let kernel_output = utxos_view
                .utxo(kernel_outpoint)
                .map_err(|_| ConsensusPoSError::FailedToFetchUtxo)?
                .ok_or(ConsensusPoSError::MissingKernelUtxo)?;

            Ok(kernel_output.take_output())
        }
        // in general this should not be an issue, but we have to first study this security model with one kernel
        _ => Err(ConsensusPoSError::MultipleKernels),
    }
}
