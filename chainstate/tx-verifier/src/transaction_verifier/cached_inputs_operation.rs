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

#[cfg(test)]
mod tests {
    use super::*;
    use common::{
        chain::{SpendablePosition, TxMainChainIndex, TxMainChainPosition},
        primitives::{Id, H256},
    };
    use crypto::random::Rng;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    fn make_tx_index(output_count: u32) -> TxMainChainIndex {
        let tx_pos = TxMainChainPosition::new(Id::new(H256::from_low_u64_le(1000000)), 0);
        let position = SpendablePosition::Transaction(tx_pos);
        TxMainChainIndex::new(position, output_count).unwrap()
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_spend_from_read(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let output_count = rng.gen::<u32>() % 100;
        let index = rng.gen::<u32>() % output_count;

        let tx_index = make_tx_index(output_count);
        let cached_operation = CachedInputsOperation::Read(tx_index.clone());

        let spender = Spender::RegularInput(Id::new(H256::random_using(&mut rng)));

        {
            let mut cached_operation = cached_operation;
            let mut tx_index = tx_index;
            tx_index.spend(index, spender.clone()).unwrap();
            cached_operation.spend(index, spender).unwrap();
            assert_eq!(
                cached_operation,
                CachedInputsOperation::Write(tx_index.clone())
            );

            tx_index.unspend(index).unwrap();
            cached_operation.unspend(index).unwrap();
            assert_eq!(cached_operation, CachedInputsOperation::Write(tx_index));
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_spend_from_write(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let output_count = rng.gen::<u32>() % 100;
        let index = rng.gen::<u32>() % output_count;

        let tx_index = make_tx_index(output_count);
        let cached_operation = CachedInputsOperation::Write(tx_index.clone());

        let spender = Spender::RegularInput(Id::new(H256::random_using(&mut rng)));

        {
            let mut cached_operation = cached_operation;
            let mut tx_index = tx_index;
            tx_index.spend(index, spender.clone()).unwrap();
            cached_operation.spend(index, spender).unwrap();
            assert_eq!(
                cached_operation,
                CachedInputsOperation::Write(tx_index.clone())
            );

            tx_index.unspend(index).unwrap();
            cached_operation.unspend(index).unwrap();
            assert_eq!(cached_operation, CachedInputsOperation::Write(tx_index));
        }
    }

    #[test]
    fn mark_as_write() {
        let output_count = 3;

        let tx_index = make_tx_index(output_count);
        let mut cached_operation = CachedInputsOperation::Read(tx_index.clone());

        cached_operation.mark_as_write();

        assert_eq!(cached_operation, CachedInputsOperation::Write(tx_index));
    }
}
