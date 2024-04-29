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

use std::sync::Arc;

use common::chain::ChainConfig;
use helpers::{InputUtxoBlockInfo, SourceTransactionInfo};
use script::MintScript;

pub mod helpers;
pub mod script;
mod timelock_check;

pub struct ScriptEvaluator {
    chain_config: Arc<ChainConfig>,
    script: MintScript,
}

impl ScriptEvaluator {
    pub fn execute(
        &self,
        source_block_info: &SourceTransactionInfo,
        blochchain_state: &InputUtxoBlockInfo,
    ) -> bool {
        self.script
            .try_into_bool(&self.chain_config, source_block_info, blochchain_state)
            .unwrap_or(false)
    }
}
