// Copyright (c) 2022 RBB S.r.l
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

use super::Block;
use crate::chain::TransactionSize;
use serialization::Encode;

pub struct BlockSize {
    header: usize,
    from_txs: usize,
    from_smart_contracts: usize,
}

impl BlockSize {
    pub fn new_from_block(block: &Block) -> Self {
        block
            .transactions()
            .iter()
            .map(|tx| tx.transaction().transaction_data_size())
            .fold(
                BlockSize::new_with_header_size(block.header().encoded_size()),
                |mut total, curr| {
                    match curr {
                        TransactionSize::ScriptedTransaction(size) => total.from_txs += size,
                        TransactionSize::SmartContractTransaction(size) => {
                            total.from_smart_contracts += size
                        }
                    };
                    total
                },
            )
    }

    fn new_with_header_size(header_size: usize) -> Self {
        BlockSize {
            header: header_size,
            from_txs: 0,
            from_smart_contracts: 0,
        }
    }

    pub fn size_from_txs(&self) -> usize {
        self.from_txs
    }

    pub fn size_from_smart_contracts(&self) -> usize {
        self.from_smart_contracts
    }

    pub fn size_from_header(&self) -> usize {
        self.header
    }
}

// TODO: write tests
