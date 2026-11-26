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

//! Types of the `dex_subscribe_to_trades` subscription.

use std::str::FromStr as _;

use chainstate_types::DexTradeInfo;
use common::{
    chain::{Block, Currency, Transaction, tokens::TokenId},
    primitives::{BlockHeight, H256, Id},
};
use rpc::description::{HasValueHint, ValueHint};

/// The literal that stands for the native coin in a trading pair.
const COIN: &str = "coin";

/// A trading pair used to filter the trades of `dex_subscribe_to_trades`.
///
/// The base is the currency the maker gives, the quote is the currency the maker asks for.
/// Each of them is either the literal `"coin"` or the hex-encoded id of a token.
/// A trade matches a pair only if both of its sides match: a pair is directional and a trade
/// of the reversed pair does not match it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RpcTradingPair {
    pub base: String,
    pub quote: String,
}

/// A trading pair that is not well-formed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "invalid {side} of the trading pair: {value:?} is neither \"{COIN}\" nor a hex-encoded token id"
)]
pub struct RpcTradingPairError {
    side: &'static str,
    value: String,
}

impl RpcTradingPair {
    /// Validate the pair, resolving its sides into currencies.
    pub fn parse(&self) -> Result<TradingPair, RpcTradingPairError> {
        let base = parse_currency("base", &self.base)?;
        let quote = parse_currency("quote", &self.quote)?;
        Ok(TradingPair { base, quote })
    }
}

fn parse_currency(side: &'static str, value: &str) -> Result<Currency, RpcTradingPairError> {
    let error = || RpcTradingPairError {
        side,
        value: value.to_owned(),
    };
    if value == COIN {
        return Ok(Currency::Coin);
    }
    // the canonical hex form of the ids of the events: 64 hex digits, no prefix
    if value.starts_with("0x") || value.starts_with("0X") {
        return Err(error());
    }
    let token_id = H256::from_str(value).map_err(|_| error())?;
    Ok(Currency::Token(TokenId::new(token_id)))
}

/// A validated [`RpcTradingPair`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TradingPair {
    pub base: Currency,
    pub quote: Currency,
}

impl TradingPair {
    /// Whether the trade has exactly this pair.
    pub fn matches(&self, trade: &DexTradeInfo) -> bool {
        self.base == trade.base && self.quote == trade.quote
    }
}

/// An event of `dex_subscribe_to_trades`: one DEX trade (an order fill) of a block that became
/// the best chain.
///
/// The trade is described from the point of view of the maker (the order being filled): the base
/// is the currency the maker gives and the quote is the currency the maker asks for, so the
/// price of the trade in quote per base is `quote_amount / base_amount`. The amounts are in
/// atoms.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum RpcDexTradeEvent {
    DexTrade {
        /// The transaction containing the fill-order input.
        tx_id: Id<Transaction>,
        /// The position of the fill-order input in the transaction inputs.
        input_ordinal: u32,
        /// The position of the match among the matches of the input (always 0 for now).
        match_ordinal: u32,
        /// The currency the maker gives: `"coin"` or the hex-encoded token id.
        base_token_id: String,
        /// The currency the maker asks for: `"coin"` or the hex-encoded token id.
        quote_token_id: String,
        /// The amount of base paid out by the maker, in atoms.
        base_amount: String,
        /// The amount of quote paid by the taker, in atoms.
        quote_amount: String,
        /// The hex-encoded id of the order that was filled.
        maker_order_id: String,
        /// The block containing the transaction.
        block_id: Id<Block>,
        /// The height of the block.
        block_height: BlockHeight,
        /// The position of the trade in the block:
        /// `(tx_index << 20) | (input_ordinal << 4) | match_ordinal`; below 2^40.
        in_block_position: u64,
    },
}

impl RpcDexTradeEvent {
    pub fn from_trade(trade: &DexTradeInfo) -> Self {
        RpcDexTradeEvent::DexTrade {
            tx_id: trade.tx_id,
            input_ordinal: trade.input_ordinal,
            match_ordinal: trade.match_ordinal,
            base_token_id: currency_to_string(&trade.base),
            quote_token_id: currency_to_string(&trade.quote),
            base_amount: trade.base_amount.into_atoms().to_string(),
            quote_amount: trade.quote_amount.into_atoms().to_string(),
            maker_order_id: format!("{:x}", trade.maker_order_id),
            block_id: trade.block_id,
            block_height: trade.block_height,
            in_block_position: trade.in_block_position(),
        }
    }
}

/// The currency in the form accepted by [`RpcTradingPair`]: `"coin"` or the hex-encoded token id.
fn currency_to_string(currency: &Currency) -> String {
    match currency {
        Currency::Coin => COIN.to_owned(),
        Currency::Token(token_id) => format!("{token_id:x}"),
    }
}

/// The hint of a trading pair.
const PAIR_HINT: ValueHint =
    ValueHint::Object(&[("base", &CURRENCY_HINT), ("quote", &CURRENCY_HINT)]);

impl HasValueHint for RpcTradingPair {
    const HINT_SER: ValueHint = PAIR_HINT;
    const HINT_DE: ValueHint = PAIR_HINT;
}

impl HasValueHint for RpcDexTradeEvent {
    const HINT_SER: ValueHint = ValueHint::Object(&[
        ("type", &ValueHint::StrLit("DexTrade")),
        ("tx_id", &ValueHint::HEX_STRING),
        ("input_ordinal", &ValueHint::NUMBER),
        ("match_ordinal", &ValueHint::NUMBER),
        ("base_token_id", &CURRENCY_HINT),
        ("quote_token_id", &CURRENCY_HINT),
        ("base_amount", &ValueHint::NUMBER_STRING),
        ("quote_amount", &ValueHint::NUMBER_STRING),
        ("maker_order_id", &ValueHint::HEX_STRING),
        ("block_id", &ValueHint::HEX_STRING),
        ("block_height", &ValueHint::NUMBER),
        ("in_block_position", &ValueHint::NUMBER),
    ]);
}

/// The hint of a trading pair side.
const CURRENCY_HINT: ValueHint =
    ValueHint::Choice(&[&ValueHint::StrLit(COIN), &ValueHint::HEX_STRING]);

#[cfg(test)]
mod tests {
    use super::*;
    use chainstate_types::DexTradeMatch;
    use common::{chain::OrderId, primitives::Amount};

    fn token_id(low: u64) -> TokenId {
        TokenId::new(H256::from_low_u64_be(low))
    }

    fn trade(base: Currency, quote: Currency, tx_low: u64) -> DexTradeInfo {
        DexTradeInfo::new(
            Id::new(H256::from_low_u64_be(0x11)),
            BlockHeight::new(7),
            3,
            DexTradeMatch {
                tx_id: Id::new(H256::from_low_u64_be(tx_low)),
                input_ordinal: 1,
                match_ordinal: 0,
                maker_order_id: OrderId::new(H256::from_low_u64_be(0x22)),
                base,
                quote,
                base_amount: Amount::from_atoms(u128::MAX),
                quote_amount: Amount::from_atoms(1234),
            },
        )
        .unwrap()
    }

    fn pair(base: &str, quote: &str) -> RpcTradingPair {
        RpcTradingPair {
            base: base.to_owned(),
            quote: quote.to_owned(),
        }
    }

    #[test]
    fn json_shape() {
        let token = token_id(0xab);
        let event =
            RpcDexTradeEvent::from_trade(&trade(Currency::Coin, Currency::Token(token), 0xcd));
        let json = serde_json::to_value(&event).unwrap();

        // the type tag is a field of the event, and the fields are inline
        let object = json.as_object().unwrap();
        assert_eq!(object.len(), 12);
        assert_eq!(json["type"], "DexTrade");
        assert_eq!(
            json["tx_id"],
            format!("{:x}", Id::<Transaction>::new(H256::from_low_u64_be(0xcd)))
        );
        assert_eq!(json["input_ordinal"], 1);
        assert_eq!(json["match_ordinal"], 0);
        assert_eq!(json["base_token_id"], "coin");
        assert_eq!(json["quote_token_id"], format!("{token:x}"));
        // the amounts are atom strings, without any loss of precision
        assert_eq!(json["base_amount"], u128::MAX.to_string());
        assert_eq!(json["quote_amount"], "1234");
        assert_eq!(
            json["maker_order_id"],
            format!("{:x}", OrderId::new(H256::from_low_u64_be(0x22)))
        );
        assert_eq!(
            json["block_id"],
            format!("{:x}", Id::<Block>::new(H256::from_low_u64_be(0x11)))
        );
        assert_eq!(json["block_height"], 7);
        assert_eq!(json["in_block_position"], (3u64 << 20) | (1 << 4));

        // the event deserializes back (the client side of the subscription)
        assert_eq!(
            serde_json::from_value::<RpcDexTradeEvent>(json).unwrap(),
            event
        );
    }

    #[test]
    fn pair_filter_selects_and_rejects() {
        let token = token_id(0xab);
        let other_token = token_id(0xcd);
        let coin_token = trade(Currency::Coin, Currency::Token(token), 1);
        let token_coin = trade(Currency::Token(token), Currency::Coin, 2);
        let token_token = trade(Currency::Token(token), Currency::Token(other_token), 3);

        let coin_token_pair = pair("coin", &format!("{token:x}")).parse().unwrap();
        assert!(coin_token_pair.matches(&coin_token));
        // the reversed pair does not match
        assert!(!coin_token_pair.matches(&token_coin));
        assert!(!coin_token_pair.matches(&token_token));

        let token_coin_pair = pair(&format!("{token:x}"), "coin").parse().unwrap();
        assert!(token_coin_pair.matches(&token_coin));
        assert!(!token_coin_pair.matches(&coin_token));

        let coin_coin_pair = pair("coin", "coin").parse().unwrap();
        assert!(coin_coin_pair.matches(&trade(Currency::Coin, Currency::Coin, 4)));
        assert!(!coin_coin_pair.matches(&coin_token));

        let token_token_pair =
            pair(&format!("{token:x}"), &format!("{other_token:x}")).parse().unwrap();
        assert!(token_token_pair.matches(&token_token));
        assert!(!token_token_pair.matches(&trade(
            Currency::Token(other_token),
            Currency::Token(token),
            5
        )));

        // a well-formed pair of a token that does not exist is accepted and matches nothing
        let unknown = pair(&format!("{:x}", token_id(0xff)), "coin").parse().unwrap();
        assert!(!unknown.matches(&token_coin));
    }

    #[test]
    fn pair_filter_rejects_malformed_token_ids() {
        let token = token_id(0xab);
        // the canonical form is accepted
        assert!(pair(&format!("{token:x}"), "coin").parse().is_ok());
        assert!(pair("coin", "coin").parse().is_ok());

        for malformed in [
            "".to_owned(),
            "0x".to_owned(),
            format!("0x{token:x}"),
            // shorter and longer than 32 bytes
            "abc".to_owned(),
            "ab".repeat(33),
            format!("{token:x}00"), // longer than 32 bytes
            format!("{token:x}zz"), // non-hex characters
            "Coin".to_owned(),
            " coins".to_owned(),
        ] {
            let err = pair("coin", &malformed).parse().unwrap_err();
            assert_eq!(err.side, "quote");
            assert_eq!(err.value, malformed);
            assert!(err.to_string().contains(&format!("{malformed:?}")), "{err}");
        }
        let err = pair("nope", "coin").parse().unwrap_err();
        assert_eq!(err.side, "base");
        assert_eq!(err.value, "nope");
    }

    #[test]
    fn filtered_and_unfiltered_events_are_identical() {
        let token = token_id(0xab);
        let trades = [
            trade(Currency::Coin, Currency::Token(token), 1),
            trade(Currency::Token(token), Currency::Coin, 2),
        ];
        let pairs = [pair("coin", &format!("{token:x}")).parse().unwrap()];
        let filtered: Vec<_> = trades
            .iter()
            .filter(|trade| pairs.iter().any(|pair| pair.matches(trade)))
            .map(RpcDexTradeEvent::from_trade)
            .collect();
        let unfiltered: Vec<_> = trades.iter().map(RpcDexTradeEvent::from_trade).collect();
        assert_eq!(filtered.len(), 1);
        assert_eq!(
            serde_json::to_string(&filtered[0]).unwrap(),
            serde_json::to_string(&unfiltered[0]).unwrap()
        );
    }
}
