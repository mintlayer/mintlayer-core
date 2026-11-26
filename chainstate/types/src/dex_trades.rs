// Copyright (c) 2026 RBB S.r.l
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

//! Records of the DEX trades (order fills) performed by the transactions of a block.

use common::{
    chain::{Block, Currency, OrderId, Transaction},
    primitives::{Amount, BlockHeight, Id},
};

/// One match of a fill-order input, as resolved by the transaction verifier when the
/// transaction is connected.
///
/// Today a fill input matches exactly the order it references, so every fill input yields
/// exactly one match; the record exists so that a matcher producing several matches per
/// input can yield several of them without changing the shape of the trade events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexTradeMatch {
    /// The transaction containing the fill-order input.
    pub tx_id: Id<Transaction>,
    /// The position of the fill-order input in the transaction inputs.
    pub input_ordinal: usize,
    /// The position of the match within the matches of the input (0 for the only match).
    pub match_ordinal: usize,
    /// The order that was filled (the maker's order).
    pub maker_order_id: OrderId,
    /// The currency the maker gives (`give` side of the order; the base of the pair).
    pub base: Currency,
    /// The currency the maker asks for (`ask` side of the order; the quote of the pair).
    pub quote: Currency,
    /// The amount of `base` paid out by the order (`give` payout).
    pub base_amount: Amount,
    /// The amount of `quote` taken from the taker by the fill (`ask` fill amount).
    pub quote_amount: Amount,
}

/// Number of bits of the transaction index in [`DexTradeInfo::in_block_position`].
const TX_INDEX_BITS: u32 = 20;
/// Number of bits of the input ordinal in [`DexTradeInfo::in_block_position`].
const INPUT_ORDINAL_BITS: u32 = 16;
/// Number of bits of the match ordinal in [`DexTradeInfo::in_block_position`].
const MATCH_ORDINAL_BITS: u32 = 4;

/// A trade whose position in the block cannot be encoded in [`DexTradeInfo::in_block_position`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DexTradePositionError {
    #[error("transaction index {0} is out of the in-block position bounds (must be below 2^20)")]
    TxIndexTooLarge(usize),
    #[error("input ordinal {0} is out of the in-block position bounds (must be below 2^16)")]
    InputOrdinalTooLarge(usize),
    #[error("match ordinal {0} is out of the in-block position bounds (must be below 16)")]
    MatchOrdinalTooLarge(usize),
}

/// A DEX trade positioned within a mainchain block.
///
/// The identity of a trade is the tuple
/// `(block_id, tx_id, input_ordinal, match_ordinal)`; `in_block_position` is its compact
/// in-block form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexTradeInfo {
    pub block_id: Id<Block>,
    pub block_height: BlockHeight,
    pub tx_id: Id<Transaction>,
    pub input_ordinal: u32,
    pub match_ordinal: u32,
    pub maker_order_id: OrderId,
    /// The currency the maker gives (`give` side of the order; the base of the pair).
    pub base: Currency,
    /// The currency the maker asks for (`ask` side of the order; the quote of the pair).
    pub quote: Currency,
    /// The amount of `base` paid out by the order (`give` payout).
    pub base_amount: Amount,
    /// The amount of `quote` taken from the taker by the fill (`ask` fill amount).
    pub quote_amount: Amount,
    in_block_position: u64,
}

impl DexTradeInfo {
    /// Position the match of the transaction at `tx_index` within the block.
    ///
    /// A block holds at most 1 MiB of transactions, which keeps the transaction index far below
    /// 2^20 and the input count of a transaction far below 2^16, and a fill input yields a
    /// handful of matches at most, so the position always fits; the error is a defensive guard
    /// for the contrary case.
    pub fn new(
        block_id: Id<Block>,
        block_height: BlockHeight,
        tx_index: usize,
        trade: DexTradeMatch,
    ) -> Result<Self, DexTradePositionError> {
        let DexTradeMatch {
            tx_id,
            input_ordinal,
            match_ordinal,
            maker_order_id,
            base,
            quote,
            base_amount,
            quote_amount,
        } = trade;

        if tx_index >= (1 << TX_INDEX_BITS) {
            return Err(DexTradePositionError::TxIndexTooLarge(tx_index));
        }
        if input_ordinal >= (1 << INPUT_ORDINAL_BITS) {
            return Err(DexTradePositionError::InputOrdinalTooLarge(input_ordinal));
        }
        if match_ordinal >= (1 << MATCH_ORDINAL_BITS) {
            return Err(DexTradePositionError::MatchOrdinalTooLarge(match_ordinal));
        }

        let in_block_position = compute_in_block_position(
            u64::try_from(tx_index).expect("bounded above"),
            u64::try_from(input_ordinal).expect("bounded above"),
            u64::try_from(match_ordinal).expect("bounded above"),
        );

        Ok(Self {
            block_id,
            block_height,
            tx_id,
            input_ordinal: u32::try_from(input_ordinal).expect("bounded above"),
            match_ordinal: u32::try_from(match_ordinal).expect("bounded above"),
            maker_order_id,
            base,
            quote,
            base_amount,
            quote_amount,
            in_block_position,
        })
    }

    /// The position of the trade in the block, computed from the canonical in-block indices only:
    /// `(tx_index << 20) | (input_ordinal << 4) | match_ordinal`, so that the positions of the
    /// trades of a block ordered by `(tx_index, input_ordinal, match_ordinal)` are increasing.
    ///
    /// Bounds: `tx_index < 2^20`, `input_ordinal < 2^16`, `match_ordinal < 16`; a position is
    /// therefore below 2^40, within the range of integers that every JSON client represents
    /// exactly.
    pub fn in_block_position(&self) -> u64 {
        self.in_block_position
    }
}

/// Compute [`DexTradeInfo::in_block_position`] from the components validated by [`DexTradeInfo::new`].
fn compute_in_block_position(tx_index: u64, input_ordinal: u64, match_ordinal: u64) -> u64 {
    debug_assert!(tx_index < (1 << TX_INDEX_BITS));
    debug_assert!(input_ordinal < (1 << INPUT_ORDINAL_BITS));
    debug_assert!(match_ordinal < (1 << MATCH_ORDINAL_BITS));

    tx_index
        .checked_shl(INPUT_ORDINAL_BITS + MATCH_ORDINAL_BITS)
        .and_then(|position| {
            input_ordinal
                .checked_shl(MATCH_ORDINAL_BITS)
                .map(|input_bits| position | input_bits)
        })
        .map(|position| position | match_ordinal)
        .expect("the bounds above leave room for every component")
}

#[cfg(test)]
mod tests {
    use common::{
        chain::{Block, Currency, OrderId, Transaction, tokens::TokenId},
        primitives::{Amount, BlockHeight, H256, Id},
    };

    use super::*;

    fn trade(tx_id: u64, input_ordinal: usize, match_ordinal: usize) -> DexTradeMatch {
        DexTradeMatch {
            tx_id: Id::new(H256::from_low_u64_be(tx_id)),
            input_ordinal,
            match_ordinal,
            maker_order_id: OrderId::zero(),
            base: Currency::Coin,
            quote: Currency::Token(TokenId::zero()),
            base_amount: Amount::from_atoms(1),
            quote_amount: Amount::from_atoms(2),
        }
    }

    fn info(tx_index: usize, input_ordinal: usize, match_ordinal: usize) -> DexTradeInfo {
        DexTradeInfo::new(
            Id::new(H256::from_low_u64_be(7)),
            BlockHeight::new(3),
            tx_index,
            trade(1, input_ordinal, match_ordinal),
        )
        .unwrap()
    }

    #[test]
    fn in_block_position_layout() {
        assert_eq!(info(0, 0, 0).in_block_position(), 0);
        assert_eq!(info(0, 0, 1).in_block_position(), 1);
        assert_eq!(info(0, 1, 0).in_block_position(), 1 << 4);
        assert_eq!(info(1, 0, 0).in_block_position(), 1 << 20);
        assert_eq!(info(0, 1, 1).in_block_position(), (1 << 4) | 1);
        assert_eq!(info(3, 5, 7).in_block_position(), (3 << 20) | (5 << 4) | 7);
        // the last encodable position stays below 2^40: exactly representable as a JSON number
        let last = info((1 << 20) - 1, (1 << 16) - 1, 15).in_block_position();
        assert_eq!(last, (1 << 40) - 1);
        assert!(last < (1u64 << 53));
    }

    #[test]
    fn in_block_position_bounds() {
        assert_eq!(
            DexTradeInfo::new(Id::zero(), BlockHeight::zero(), 1 << 20, trade(1, 0, 0)),
            Err(DexTradePositionError::TxIndexTooLarge(1 << 20))
        );
        assert_eq!(
            DexTradeInfo::new(Id::zero(), BlockHeight::zero(), 0, trade(1, 1 << 16, 0)),
            Err(DexTradePositionError::InputOrdinalTooLarge(1 << 16))
        );
        assert_eq!(
            DexTradeInfo::new(Id::zero(), BlockHeight::zero(), 0, trade(1, 0, 16)),
            Err(DexTradePositionError::MatchOrdinalTooLarge(16))
        );
        // the last values within the bounds are accepted
        assert!(
            DexTradeInfo::new(
                Id::zero(),
                BlockHeight::zero(),
                (1 << 20) - 1,
                trade(1, 0, 0)
            )
            .is_ok()
        );
        assert!(
            DexTradeInfo::new(
                Id::zero(),
                BlockHeight::zero(),
                0,
                trade(1, (1 << 16) - 1, 0)
            )
            .is_ok()
        );
        assert!(DexTradeInfo::new(Id::zero(), BlockHeight::zero(), 0, trade(1, 0, 15)).is_ok());
    }

    #[test]
    fn in_block_position_is_ordered_by_block_indices() {
        let mut positions = Vec::new();
        for tx_index in [0, 1, 5] {
            for input_ordinal in [0, 1, 300] {
                for match_ordinal in [0, 1, 15] {
                    positions
                        .push(info(tx_index, input_ordinal, match_ordinal).in_block_position());
                }
            }
        }
        let sorted = {
            let mut sorted = positions.clone();
            sorted.sort_unstable();
            sorted
        };
        // positions are generated in (tx_index, input_ordinal, match_ordinal) order and are
        // distinct, so they must already be sorted
        assert_eq!(positions, sorted);
        assert_eq!(
            positions.iter().collect::<std::collections::BTreeSet<_>>().len(),
            positions.len()
        );
    }

    #[test]
    fn new_copies_the_match_fields() {
        let info = DexTradeInfo::new(
            Id::new(H256::from_low_u64_be(7)),
            BlockHeight::new(3),
            2,
            trade(11, 4, 0),
        )
        .unwrap();

        assert_eq!(info.block_id, Id::<Block>::new(H256::from_low_u64_be(7)));
        assert_eq!(info.block_height, BlockHeight::new(3));
        assert_eq!(
            info.tx_id,
            Id::<Transaction>::new(H256::from_low_u64_be(11))
        );
        assert_eq!(info.input_ordinal, 4);
        assert_eq!(info.match_ordinal, 0);
        assert_eq!(info.maker_order_id, OrderId::zero());
        assert_eq!(info.base, Currency::Coin);
        assert_eq!(info.quote, Currency::Token(TokenId::zero()));
        assert_eq!(info.base_amount, Amount::from_atoms(1));
        assert_eq!(info.quote_amount, Amount::from_atoms(2));
    }
}
