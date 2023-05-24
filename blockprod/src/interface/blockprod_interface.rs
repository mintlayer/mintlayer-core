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

use common::chain::{Block, SignedTransaction};
use consensus::GenerateBlockInputData;

use crate::{detail::job_manager::JobKey, BlockProductionError};

#[async_trait::async_trait]
pub trait BlockProductionInterface: Send {
    /// When called, the job manager will be notified to send a signal
    /// to all currently running jobs to stop running
    async fn stop_all(&mut self) -> Result<usize, BlockProductionError>;

    /// Stop a specific job, given its key
    async fn stop_job(&mut self, job_id: JobKey) -> Result<bool, BlockProductionError>;

    /// Generate a block with the given transactions to the specified
    /// reward destination. If transactions are None, the block will be
    /// generated with available transactions in the mempool
    async fn generate_block(
        &mut self,
        input_data: Option<GenerateBlockInputData>,
        transactions: Option<Vec<SignedTransaction>>,
    ) -> Result<Block, BlockProductionError>;
}
