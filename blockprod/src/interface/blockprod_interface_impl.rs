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

use common::chain::{Block, Destination, SignedTransaction};

use crate::{detail::BlockProduction, BlockProductionError};

use super::blockprod_interface::BlockProductionInterface;

#[async_trait::async_trait]
impl BlockProductionInterface for BlockProduction {
    fn stop(&mut self) -> Result<(), BlockProductionError> {
        self.stop_all_jobs();
        Ok(())
    }

    async fn generate_block(
        &mut self,
        reward_destination: Destination,
        transactions: Option<Vec<SignedTransaction>>,
    ) -> Result<Block, BlockProductionError> {
        let transactions = match transactions {
            Some(txs) => crate::detail::TransactionsSource::Provided(txs),
            None => crate::detail::TransactionsSource::Mempool,
        };

        self.generate_block(reward_destination, transactions).await
    }
}
