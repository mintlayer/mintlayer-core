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

use common::{chain::ChainConfig, primitives::BlockHeight};

#[derive(Debug, Eq, PartialEq)]
pub enum EpochSealOp {
    Seal,
    Unseal,
    None,
}

impl EpochSealOp {
    pub fn new(
        chain_config: &ChainConfig,
        sealed_epoch_height: Option<BlockHeight>,
        tip_height: BlockHeight,
    ) -> Self {
        let sealed_epoch_distance_from_tip = chain_config.sealed_epoch_distance_from_tip() as u64;

        match sealed_epoch_height {
            Some(sealed_epoch_height) => {
                let current_epoch_index = chain_config.epoch_index_from_height(&tip_height);
                let sealed_epoch_index = chain_config.epoch_index_from_height(&sealed_epoch_height);
                // check if current height is due for epoch seal
                if chain_config.is_due_for_epoch_seal(&tip_height) {
                    match (sealed_epoch_index + sealed_epoch_distance_from_tip)
                        .cmp(&current_epoch_index)
                    {
                        std::cmp::Ordering::Less => return Self::Seal,
                        std::cmp::Ordering::Equal => return Self::None,
                        std::cmp::Ordering::Greater => return Self::Unseal,
                    }
                // check if next height is due for epoch seal, because it can be a case on disconnect
                } else if chain_config.is_due_for_epoch_seal(&tip_height.next_height()) {
                    // if so check that sealed epoch is far enough
                    if sealed_epoch_index + sealed_epoch_distance_from_tip >= current_epoch_index {
                        return Self::Unseal;
                    }
                }
            }
            None => {
                // start sealing only if tip epoch is far enough, after that every epoch step can be sealed
                if chain_config.is_due_for_epoch_seal(&tip_height) {
                    let tip_height: u64 = tip_height.into();
                    let first_seal_height = (chain_config.epoch_length().get()
                        + (chain_config.epoch_length().get() * sealed_epoch_distance_from_tip))
                        .checked_sub(1)
                        .expect("always positive");
                    if tip_height >= first_seal_height {
                        return Self::Seal;
                    }
                }
            }
        };
        Self::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::chain::config::Builder;
    use rstest::rstest;
    use std::num::NonZeroU64;

    #[rstest]
    //     epoch_length,           stride, sealed_height,              tip_height,           expected op
    #[case(NonZeroU64::new(1).unwrap(), 0, None,                       BlockHeight::from(0), EpochSealOp::Seal)]
    #[case(NonZeroU64::new(1).unwrap(), 0, Some(BlockHeight::from(0)), BlockHeight::from(1), EpochSealOp::Seal)]
    #[case(NonZeroU64::new(1).unwrap(), 0, Some(BlockHeight::from(1)), BlockHeight::from(1), EpochSealOp::None)]
    #[case(NonZeroU64::new(1).unwrap(), 0, Some(BlockHeight::from(1)), BlockHeight::from(0), EpochSealOp::Unseal)]
    //---------------------------------------------------------------------------------------------------------//
    #[case(NonZeroU64::new(1).unwrap(), 1, None,                       BlockHeight::from(0), EpochSealOp::None)]
    #[case(NonZeroU64::new(1).unwrap(), 1, None,                       BlockHeight::from(1), EpochSealOp::Seal)]
    #[case(NonZeroU64::new(1).unwrap(), 1, Some(BlockHeight::from(0)), BlockHeight::from(1), EpochSealOp::None)]
    #[case(NonZeroU64::new(1).unwrap(), 1, Some(BlockHeight::from(1)), BlockHeight::from(1), EpochSealOp::Unseal)]
    #[case(NonZeroU64::new(1).unwrap(), 1, Some(BlockHeight::from(1)), BlockHeight::from(2), EpochSealOp::None)]
    #[case(NonZeroU64::new(1).unwrap(), 1, Some(BlockHeight::from(1)), BlockHeight::from(3), EpochSealOp::Seal)]
    //---------------------------------------------------------------------------------------------------------//
    #[case(NonZeroU64::new(2).unwrap(), 0, None,                       BlockHeight::from(0), EpochSealOp::None)]
    #[case(NonZeroU64::new(2).unwrap(), 0, None,                       BlockHeight::from(1), EpochSealOp::Seal)]
    #[case(NonZeroU64::new(2).unwrap(), 0, Some(BlockHeight::from(1)), BlockHeight::from(1), EpochSealOp::None)]
    #[case(NonZeroU64::new(2).unwrap(), 0, Some(BlockHeight::from(1)), BlockHeight::from(2), EpochSealOp::None)]
    #[case(NonZeroU64::new(2).unwrap(), 0, Some(BlockHeight::from(1)), BlockHeight::from(3), EpochSealOp::Seal)]
    #[case(NonZeroU64::new(2).unwrap(), 0, Some(BlockHeight::from(3)), BlockHeight::from(3), EpochSealOp::None)]
    #[case(NonZeroU64::new(2).unwrap(), 0, Some(BlockHeight::from(3)), BlockHeight::from(2), EpochSealOp::Unseal)]
    //---------------------------------------------------------------------------------------------------------//
    #[case(NonZeroU64::new(2).unwrap(), 1, None,                       BlockHeight::from(0), EpochSealOp::None)]
    #[case(NonZeroU64::new(2).unwrap(), 1, None,                       BlockHeight::from(1), EpochSealOp::None)]
    #[case(NonZeroU64::new(2).unwrap(), 1, None,                       BlockHeight::from(2), EpochSealOp::None)]
    #[case(NonZeroU64::new(2).unwrap(), 1, None,                       BlockHeight::from(3), EpochSealOp::Seal)]
    #[case(NonZeroU64::new(2).unwrap(), 1, Some(BlockHeight::from(1)), BlockHeight::from(2), EpochSealOp::Unseal)]
    #[case(NonZeroU64::new(2).unwrap(), 1, Some(BlockHeight::from(1)), BlockHeight::from(3), EpochSealOp::None)]
    #[case(NonZeroU64::new(2).unwrap(), 1, Some(BlockHeight::from(1)), BlockHeight::from(4), EpochSealOp::None)]
    #[case(NonZeroU64::new(2).unwrap(), 1, Some(BlockHeight::from(1)), BlockHeight::from(5), EpochSealOp::Seal)]
    #[case(NonZeroU64::new(2).unwrap(), 1, Some(BlockHeight::from(3)), BlockHeight::from(5), EpochSealOp::None)]
    #[case(NonZeroU64::new(2).unwrap(), 1, Some(BlockHeight::from(3)), BlockHeight::from(4), EpochSealOp::Unseal)]
    fn epoch_seal_op(
        #[case] epoch_length: NonZeroU64,
        #[case] seal_to_tip_distance: usize,
        #[case] sealed_epoch_height: Option<BlockHeight>,
        #[case] tip: BlockHeight,
        #[case] expected: EpochSealOp,
    ) {
        let config = Builder::test_chain()
            .epoch_length(epoch_length)
            .sealed_epoch_distance_from_tip(seal_to_tip_distance)
            .build();
        let op = EpochSealOp::new(&config, sealed_epoch_height, tip);
        assert_eq!(expected, op);
    }
}
