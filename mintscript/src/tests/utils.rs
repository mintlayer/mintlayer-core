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

use super::*;

pub struct MockContext<'a, C> {
    chain_config: C,
    input_num: usize,
    transaction: &'a SignedTransaction,
    input_commitments: Vec<SighashInputCommitment<'a>>,
    source_height: BlockHeight,
    spending_height: BlockHeight,
    source_time: BlockTimestamp,
    spending_time: BlockTimestamp,
}

impl<'a> MockContext<'a, ChainConfig> {
    /// New mock context
    pub fn new(
        input_num: usize,
        transaction: &'a SignedTransaction,
        input_commitments: Vec<SighashInputCommitment<'a>>,
    ) -> Self {
        Self {
            input_num,
            transaction,
            input_commitments,
            source_height: BlockHeight::zero(),
            spending_height: BlockHeight::one(),
            source_time: BlockTimestamp::from_int_seconds(0),
            spending_time: BlockTimestamp::from_int_seconds(0),
            chain_config: common::chain::config::create_regtest(),
        }
    }
}

impl<'a, C> MockContext<'a, C> {
    pub fn with_block_heights(mut self, source: BlockHeight, spending: BlockHeight) -> Self {
        self.source_height = source;
        self.spending_height = spending;
        self
    }

    pub fn with_timestamps(mut self, source: BlockTimestamp, spending: BlockTimestamp) -> Self {
        self.source_time = source;
        self.spending_time = spending;
        self
    }

    #[allow(unused)]
    pub fn with_chain_config<CC>(self, chain_config: CC) -> MockContext<'a, CC> {
        let Self {
            chain_config: _,
            input_num,
            transaction,
            input_commitments,
            source_height,
            spending_height,
            source_time,
            spending_time,
        } = self;

        MockContext {
            chain_config,
            input_num,
            transaction,
            input_commitments,
            source_height,
            spending_height,
            source_time,
            spending_time,
        }
    }

    pub fn into_checker(self) -> crate::checker::FullScriptChecker<Self> {
        crate::ScriptChecker::full(self)
    }
}

impl<C: AsRef<ChainConfig>> MockContext<'_, C> {
    pub fn chain_config(&self) -> &ChainConfig {
        self.chain_config.as_ref()
    }
}

impl<C: AsRef<ChainConfig>> crate::SignatureContext for MockContext<'_, C> {
    type Tx = SignedTransaction;

    fn chain_config(&self) -> &ChainConfig {
        self.chain_config()
    }

    fn transaction(&self) -> &Self::Tx {
        self.transaction
    }

    fn input_commitments(&self) -> &[SighashInputCommitment<'_>] {
        self.input_commitments.as_slice()
    }

    fn input_num(&self) -> usize {
        self.input_num
    }
}

impl<C> crate::TimelockContext for MockContext<'_, C> {
    type Error = std::convert::Infallible;

    fn spending_height(&self) -> BlockHeight {
        self.spending_height
    }

    fn spending_time(&self) -> BlockTimestamp {
        self.spending_time
    }

    fn source_height(&self) -> Result<BlockHeight, Self::Error> {
        Ok(self.source_height)
    }

    fn source_time(&self) -> Result<BlockTimestamp, Self::Error> {
        Ok(self.source_time)
    }
}

// Timelock creation helpers

pub const fn tl_until_height(b: u64) -> OutputTimeLock {
    OutputTimeLock::UntilHeight(BlockHeight::new(b))
}

pub const fn tl_for_blocks(n: u64) -> OutputTimeLock {
    OutputTimeLock::ForBlockCount(n)
}

pub const fn tl_until_time(t: u64) -> OutputTimeLock {
    OutputTimeLock::UntilTime(BlockTimestamp::from_int_seconds(t))
}

pub const fn tl_for_secs(s: u64) -> OutputTimeLock {
    OutputTimeLock::ForSeconds(s)
}
