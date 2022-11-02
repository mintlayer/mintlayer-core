// Copyright (c) 2021-2022 RBB S.r.l
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

use super::{error::TxIndexError, CachedOperation};
use common::chain::{Spender, TxMainChainIndex};

pub type CachedInputsOperation = CachedOperation<TxMainChainIndex>;

impl CachedInputsOperation {
    pub fn spend(&mut self, output_index: u32, spender: Spender) -> Result<(), TxIndexError> {
        // spend the output
        match self {
            CachedInputsOperation::Write(tx_index) | CachedInputsOperation::Read(tx_index) => {
                tx_index.spend(output_index, spender).map_err(TxIndexError::from)?
            }
            CachedInputsOperation::Erase => {
                return Err(TxIndexError::MissingOutputOrSpentOutputErasedOnConnect)
            }
        }

        self.mark_as_write();

        Ok(())
    }

    pub fn unspend(&mut self, output_index: u32) -> Result<(), TxIndexError> {
        // unspend the output
        match self {
            CachedInputsOperation::Write(tx_index) | CachedInputsOperation::Read(tx_index) => {
                tx_index.unspend(output_index).map_err(TxIndexError::from)?
            }
            CachedInputsOperation::Erase => {
                return Err(TxIndexError::MissingOutputOrSpentOutputErasedOnDisconnect)
            }
        }

        self.mark_as_write();

        Ok(())
    }

    fn mark_as_write(&mut self) {
        // replace &mut self with a new value (must be done like this because it's unsafe)
        let replacer_func = |self_| match self_ {
            CachedInputsOperation::Write(tx_index) => CachedInputsOperation::Write(tx_index),
            CachedInputsOperation::Read(tx_index) => CachedInputsOperation::Write(tx_index),
            CachedInputsOperation::Erase => unreachable!(),
        };
        replace_with::replace_with_or_abort(self, replacer_func);
    }
}

// TODO: tests
