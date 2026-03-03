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

use std::{collections::BTreeMap, fmt::Display, str::FromStr};

use bigdecimal::BigDecimal;
use clap::ValueEnum;
use itertools::Itertools;

use chainstate::rpc::RpcOutputValueOut;
use common::{
    address::{decode_address, Address, AddressError, RpcAddress},
    chain::{
        block::timestamp::BlockTimestamp,
        timelock::OutputTimeLock,
        tokens::{RPCTokenInfo, TokenId},
        ChainConfig, Currency, Destination, OrderId, OutPointSourceId, TxOutput, UtxoOutPoint,
    },
    primitives::{
        amount::decimal::{
            subtract_decimal_amounts_of_same_currency, DecimalAmountWithIsSameComparison,
        },
        time::Time,
        BlockHeight, DecimalAmount, Id, H256,
    },
};
use utils::ensure;
use wallet_controller::types::{
    GenericCurrencyTransfer, GenericCurrencyTransferToTxOutputConversionError, GenericTokenTransfer,
};
use wallet_rpc_lib::types::{ActiveOrderInfo, OwnOrderInfo, PoolInfo, TokenTotalSupply};
use wallet_types::{
    seed_phrase::StoreSeedPhrase,
    utxo_types::{UtxoState, UtxoType},
    with_locked::WithLocked,
};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliUtxoTypes {
    All,
    Transfer,
    LockThenTransfer,
    CreateStakePool,
    ProduceBlockFromStake,
}

impl CliUtxoTypes {
    pub fn to_wallet_types(self) -> Vec<UtxoType> {
        match self {
            CliUtxoTypes::All => vec![
                UtxoType::Transfer,
                UtxoType::LockThenTransfer,
                UtxoType::CreateStakePool,
                UtxoType::ProduceBlockFromStake,
            ],
            CliUtxoTypes::Transfer => vec![UtxoType::Transfer],
            CliUtxoTypes::LockThenTransfer => vec![UtxoType::LockThenTransfer],
            CliUtxoTypes::CreateStakePool => vec![UtxoType::CreateStakePool],
            CliUtxoTypes::ProduceBlockFromStake => vec![UtxoType::ProduceBlockFromStake],
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliUtxoState {
    Confirmed,
    Conflicted,
    InMempool,
    Inactive,
    Abandoned,
}

impl Display for CliUtxoState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // naming is kept the same as the default parse provided by ValueEnum
        match self {
            CliUtxoState::Confirmed => f.write_str("confirmed"),
            CliUtxoState::Conflicted => f.write_str("conflicted"),
            CliUtxoState::InMempool => f.write_str("in-mempool"),
            CliUtxoState::Inactive => f.write_str("inactive"),
            CliUtxoState::Abandoned => f.write_str("abandoned"),
        }
    }
}

impl CliUtxoState {
    pub fn to_wallet_type(self) -> UtxoState {
        match self {
            CliUtxoState::Confirmed => UtxoState::Confirmed,
            CliUtxoState::Conflicted => UtxoState::Conflicted,
            CliUtxoState::InMempool => UtxoState::InMempool,
            CliUtxoState::Inactive => UtxoState::Inactive,
            CliUtxoState::Abandoned => UtxoState::Abandoned,
        }
    }

    pub fn to_wallet_states(value: Vec<CliUtxoState>) -> Vec<UtxoState> {
        if !value.is_empty() {
            value.iter().map(|s| s.to_wallet_type()).collect()
        } else {
            vec![UtxoState::Confirmed]
        }
    }
}

pub fn format_pool_info(info: PoolInfo) -> String {
    format!(
        concat!(
            "Pool Id: {}, Pledge: {}, Balance: {}, Creation Block Height: {}, Creation block timestamp: {}, ",
            "Staker: {}, Decommission Key: {}, VRF Public Key: {}"
        ),
        info.pool_id, info.pledge.decimal(), info.balance.decimal(), info.height, info.block_timestamp,
        info.staker, info.decommission_key, info.vrf_public_key
    )
}

pub fn format_own_order_info(
    order_info: &OwnOrderInfo,
    chain_config: &ChainConfig,
    token_infos: &BTreeMap<TokenId, RPCTokenInfo>,
) -> Result<String, FormatError> {
    if let Some(existing_order_data) = &order_info.existing_order_data {
        // The order exists on chain
        let accumulated_ask_amount = subtract_decimal_amounts_of_same_currency(
            &order_info.initially_asked.amount().decimal(),
            &existing_order_data.ask_balance.decimal(),
        )
        .ok_or_else(|| {
            FormatError::OrderNegativeAccumulatedAskAmount(order_info.order_id.clone())
        })?;
        let status = if !existing_order_data.is_frozen
            && !order_info.is_marked_as_frozen_in_wallet
            && !order_info.is_marked_as_concluded_in_wallet
        {
            "Active".to_owned()
        } else {
            let frozen_status = match (
                existing_order_data.is_frozen,
                order_info.is_marked_as_frozen_in_wallet,
            ) {
                // Note: it's technically possible for the order to be frozen but not marked as such
                // in the wallet, e.g. when the wallet hasn't scanned the corresponding block yet.
                (true, _) => Some("Frozen"),
                (false, true) => Some("Frozen (unconfirmed)"),
                (false, false) => None,
            };
            let concluded_status =
                order_info.is_marked_as_concluded_in_wallet.then_some("Concluded (unconfirmed)");

            frozen_status.iter().chain(concluded_status.iter()).join(", ")
        };
        Ok(format!(
            concat!(
                "Id: {id}, ",
                "Asked: {ia} [left: {ra}, can withdraw: {aa}], ",
                "Given: {ig} [left: {rg}], ",
                "Created at: {ts}, ",
                "Status: {st}"
            ),
            id = order_info.order_id,
            ia = format_output_value(&order_info.initially_asked, chain_config, token_infos)?,
            ra = existing_order_data.ask_balance.decimal(),
            aa = accumulated_ask_amount,
            ig = format_output_value(&order_info.initially_given, chain_config, token_infos)?,
            rg = existing_order_data.give_balance.decimal(),
            ts = existing_order_data.creation_timestamp.into_time(),
            st = status,
        ))
    } else {
        // The order only exists in the wallet
        Ok(format!(
            concat!(
                "Id: {id}, ",
                "Asked: {ia}, ",
                "Given: {ig}, ",
                "Status: Unconfirmed"
            ),
            id = order_info.order_id,
            ia = format_output_value(&order_info.initially_asked, chain_config, token_infos)?,
            ig = format_output_value(&order_info.initially_given, chain_config, token_infos)?,
        ))
    }
}

pub fn active_order_infos_header() -> &'static str {
    concat!(
        "The list of active orders goes below, orders belonging to this account are marked with '*'.\n",
        "WARNING: token tickers are not unique, always check the token id when buying a token."
    )
}

pub fn format_active_order_info(
    order_info: &ActiveOrderInfo,
    give_ask_price: &BigDecimal,
    chain_config: &ChainConfig,
    token_infos: &BTreeMap<TokenId, RPCTokenInfo>,
) -> Result<String, FormatError> {
    // Note: we show what's given first because the orders are sorted by the given currency first
    // by the caller code.
    Ok(format!(
        concat!(
            "{marker} ",
            "Id: {id}, ",
            "Given: {g} [left: {rg}], ",
            "Asked: {a} [left: {ra}], ",
            "Give/Ask: {price}"
        ),
        marker = if order_info.is_own { "*" } else { " " },
        id = order_info.order_id,
        g = format_asset_name(&order_info.initially_given, chain_config, token_infos)?,
        a = format_asset_name(&order_info.initially_asked, chain_config, token_infos)?,
        rg = order_info.give_balance.decimal(),
        ra = order_info.ask_balance.decimal(),
        price = give_ask_price.normalized(),
    ))
}

pub fn format_asset_name(
    value: &RpcOutputValueOut,
    chain_config: &ChainConfig,
    token_infos: &BTreeMap<TokenId, RPCTokenInfo>,
) -> Result<String, FormatError> {
    let result = if let Some(token_id) = value.token_id() {
        format_token_name(token_id, chain_config, token_infos)?
    } else {
        chain_config.coin_ticker().to_owned()
    };
    Ok(result)
}

pub fn format_output_value(
    value: &RpcOutputValueOut,
    chain_config: &ChainConfig,
    token_infos: &BTreeMap<TokenId, RPCTokenInfo>,
) -> Result<String, FormatError> {
    let asset_name = format_asset_name(value, chain_config, token_infos)?;
    Ok(format!("{} {}", value.amount().decimal(), asset_name))
}

pub fn format_token_name(
    token_id: &RpcAddress<TokenId>,
    chain_config: &ChainConfig,
    token_infos: &BTreeMap<TokenId, RPCTokenInfo>,
) -> Result<String, FormatError> {
    let decoded_token_id = token_id
        .decode_object(chain_config)
        .map_err(FormatError::TokenIdDecodingError)?;

    let result = if let Some(token_ticker) =
        token_infos.get(&decoded_token_id).map(token_ticker_from_rpc_token_info)
    {
        format!("{} ({token_ticker})", token_id.as_str())
    } else {
        token_id.as_str().to_owned()
    };

    Ok(result)
}

pub fn token_ticker_from_rpc_token_info(info: &RPCTokenInfo) -> &str {
    // Note: all token tickers must be alphanumeric strings, so this "???" should not be possible
    // in reality.
    str::from_utf8(info.token_ticker()).unwrap_or("???")
}

pub fn format_delegation_info(delegation_id: String, balance: String) -> String {
    format!("Delegation Id: {}, Balance: {}", delegation_id, balance)
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliWithLocked {
    Any,
    Unlocked,
    Locked,
}

impl CliWithLocked {
    pub fn to_wallet_type(self) -> WithLocked {
        match self {
            CliWithLocked::Any => WithLocked::Any,
            CliWithLocked::Unlocked => WithLocked::Unlocked,
            CliWithLocked::Locked => WithLocked::Locked,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliStoreSeedPhrase {
    StoreSeedPhrase,
    DoNotStoreSeedPhrase,
}

impl CliStoreSeedPhrase {
    pub fn to_bool(self) -> bool {
        match self {
            Self::StoreSeedPhrase => true,
            Self::DoNotStoreSeedPhrase => false,
        }
    }
}

impl From<CliStoreSeedPhrase> for StoreSeedPhrase {
    fn from(value: CliStoreSeedPhrase) -> Self {
        match value {
            CliStoreSeedPhrase::StoreSeedPhrase => StoreSeedPhrase::Store,
            CliStoreSeedPhrase::DoNotStoreSeedPhrase => StoreSeedPhrase::DoNotStore,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliEnableOrDisable {
    Enable,
    Disable,
}

impl CliEnableOrDisable {
    pub fn is_enable(self) -> bool {
        match self {
            Self::Enable => true,
            Self::Disable => false,
        }
    }
}

/// A UtxoOutPoint that can be parsed from strings of the form `tx(H256,u32)` or `block(H256,u32)`,
/// e.g. `tx(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,1)`,
/// `block(000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c,2)`
#[derive(Debug, Clone)]
pub struct CliUtxoOutPoint {
    pub source_id: OutPointSourceId,
    pub output_index: u32,
}

impl FromStr for CliUtxoOutPoint {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (name, mut args) = parse_funclike_expr(input).ok_or(ParseError::InvalidInputFormat)?;

        let (h256_str, output_index_str) = match (args.next(), args.next(), args.next()) {
            (Some(h256_str), Some(output_index_str), None) => (h256_str, output_index_str),
            (_, _, _) => {
                return Err(ParseError::InvalidInputFormat);
            }
        };

        let h256 =
            H256::from_str(h256_str).map_err(|_| ParseError::InvalidHash(h256_str.to_owned()))?;

        let output_index = u32::from_str(output_index_str)
            .map_err(|_| ParseError::InvalidOutputIndex(output_index_str.to_owned()))?;

        let source_id = if name.eq_ignore_ascii_case("tx") {
            OutPointSourceId::Transaction(Id::new(h256))
        } else if name.eq_ignore_ascii_case("block") {
            OutPointSourceId::BlockReward(Id::new(h256))
        } else {
            return Err(ParseError::UnknownSourceIdType(name.to_owned()));
        };

        Ok(Self {
            source_id,
            output_index,
        })
    }
}

impl From<CliUtxoOutPoint> for UtxoOutPoint {
    fn from(value: CliUtxoOutPoint) -> Self {
        Self::new(value.source_id, value.output_index)
    }
}

/// This represents a transfer of an amount of an unspecified currency and can be parsed
/// from strings of the form `transfer(address,amount)`.
#[derive(Debug, Clone)]
pub struct CliUnspecifiedCurrencyTransfer {
    pub amount: DecimalAmount,
    pub destination: String,
}

impl FromStr for CliUnspecifiedCurrencyTransfer {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (name, mut args) = parse_funclike_expr(input).ok_or(ParseError::InvalidInputFormat)?;

        let (dest_str, amount_str) = match (args.next(), args.next(), args.next()) {
            (Some(dest_str), Some(amount_str), None) => (dest_str, amount_str),
            (_, _, _) => {
                return Err(ParseError::InvalidInputFormat);
            }
        };

        let amount = parse_decimal_amount(amount_str)?;

        let result = if name.eq_ignore_ascii_case("transfer") {
            Self {
                amount,
                destination: dest_str.to_owned(),
            }
        } else {
            return Err(ParseError::UnknownAction(name.to_owned()));
        };

        Ok(result)
    }
}

impl CliUnspecifiedCurrencyTransfer {
    pub fn to_fully_parsed(
        &self,
        chain_config: &ChainConfig,
    ) -> Result<GenericCurrencyTransfer, ParseError> {
        Ok(GenericCurrencyTransfer {
            amount: self.amount,
            destination: parse_destination(chain_config, &self.destination)?,
        })
    }

    pub fn to_coin_tx_output(&self, chain_config: &ChainConfig) -> Result<TxOutput, ParseError> {
        Ok(self.to_fully_parsed(chain_config)?.into_coin_tx_output(chain_config)?)
    }
}

/// This represents a transfer of an amount of a token and can be parsed
/// from strings of the form `transfer(token_id,address,amount)`.
#[derive(Debug, Clone)]
pub struct CliTokenTransfer {
    pub token_id: String,
    pub amount: DecimalAmount,
    pub destination: String,
}

impl FromStr for CliTokenTransfer {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (name, mut args) = parse_funclike_expr(input).ok_or(ParseError::InvalidInputFormat)?;

        let (token_id_str, dest_str, amount_str) =
            match (args.next(), args.next(), args.next(), args.next()) {
                (Some(dest_str), Some(amount_str), Some(token_id_str), None) => {
                    (dest_str, amount_str, token_id_str)
                }
                (_, _, _, _) => {
                    return Err(ParseError::InvalidInputFormat);
                }
            };

        let amount = parse_decimal_amount(amount_str)?;

        let result = if name.eq_ignore_ascii_case("transfer") {
            Self {
                token_id: token_id_str.to_owned(),
                amount,
                destination: dest_str.to_owned(),
            }
        } else {
            return Err(ParseError::UnknownAction(name.to_owned()));
        };

        Ok(result)
    }
}

impl CliTokenTransfer {
    pub fn to_fully_parsed(
        &self,
        chain_config: &ChainConfig,
    ) -> Result<GenericTokenTransfer, ParseError> {
        let token_id = Address::from_string(chain_config, &self.token_id)
            .map_err(|_| ParseError::InvalidTokenId(self.token_id.clone()))?
            .into_object();

        let destination = parse_destination(chain_config, &self.destination)?;

        Ok(GenericTokenTransfer {
            token_id,
            amount: self.amount,
            destination,
        })
    }
}

/// Parse simple strings of the form "foo(x,y,z)".
fn parse_funclike_expr(input: &str) -> Option<(&str, impl Iterator<Item = &'_ str>)> {
    let input = input.trim();
    let (last_char, input) = pop_char_from_str(input);

    if last_char != Some(')') {
        return None;
    }

    let parens_pos = input.find('(')?;

    // Note: parens_pos is known to be at the character boundary.
    #[allow(clippy::string_slice)]
    let (func_name, input) = {
        (
            &input[..parens_pos].trim(),
            skip_char_from_str(&input[parens_pos..]).1,
        )
    };

    let args = input.split(',').map(|s| s.trim());

    Some((func_name, args))
}

fn skip_char_from_str(s: &str) -> (Option<char>, &str) {
    let mut chars = s.chars();
    let last_ch = chars.next();
    (last_ch, chars.as_str())
}

fn pop_char_from_str(s: &str) -> (Option<char>, &str) {
    let mut chars = s.chars();
    let last_ch = chars.next_back();
    (last_ch, chars.as_str())
}

/// A TokenTotalSupply that can be parsed from strings "unlimited", "lockable" and "fixed(amount)".
#[derive(Debug, Clone)]
pub enum CliTokenTotalSupply {
    Unlimited,
    Lockable,
    Fixed(DecimalAmount),
}

impl FromStr for CliTokenTotalSupply {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.eq_ignore_ascii_case("unlimited") {
            Ok(Self::Unlimited)
        } else if input.eq_ignore_ascii_case("lockable") {
            Ok(Self::Lockable)
        } else {
            let (name, mut args) =
                parse_funclike_expr(input).ok_or(ParseError::InvalidInputFormat)?;

            ensure!(
                name.eq_ignore_ascii_case("fixed"),
                ParseError::UnknownTokenSupplyType(name.to_owned())
            );

            let amount_str = match (args.next(), args.next()) {
                (Some(amount_str), None) => amount_str,
                (_, _) => {
                    return Err(ParseError::InvalidInputFormat);
                }
            };

            Ok(Self::Fixed(parse_decimal_amount(amount_str)?))
        }
    }
}

impl CliTokenTotalSupply {
    pub fn to_fully_parsed(
        &self,
        token_number_of_decimals: u8,
    ) -> Result<TokenTotalSupply, ParseError> {
        let result = match self {
            Self::Unlimited => TokenTotalSupply::Unlimited,
            Self::Lockable => TokenTotalSupply::Lockable,
            Self::Fixed(amount) => {
                // Note: even though `RpcAmountIn` can be constructed from `DecimalAmount` directly,
                // we want to do the conversion to atoms early, to produce a nicer error message.
                let amount = amount.to_amount(token_number_of_decimals).ok_or(
                    ParseError::DecimalAmountNotConvertibleToAtoms((*amount).into()),
                )?;
                TokenTotalSupply::Fixed(amount.into())
            }
        };

        Ok(result)
    }
}

/// An OutputTimeLock that can be parsed from strings of the form "block_count(num)", "seconds(num)",
/// "until_height(num)" and "until_time(RFC 3339 datetime)".
#[derive(Debug, Clone)]
pub enum CliOutputTimeLock {
    UntilHeight(BlockHeight),
    UntilTime(BlockTimestamp),
    ForBlockCount(u64),
    ForSeconds(u64),
}

impl FromStr for CliOutputTimeLock {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (lock_type, mut args) =
            parse_funclike_expr(input).ok_or(ParseError::InvalidInputFormat)?;

        let arg = match (args.next(), args.next()) {
            (Some(arg), None) => arg,
            (_, _) => {
                return Err(ParseError::InvalidInputFormat);
            }
        };

        let parse_u64 = |s: &str| -> Result<u64, _> {
            s.parse().map_err(|_| ParseError::InvalidNumber(s.to_owned()))
        };

        let result = if lock_type.eq_ignore_ascii_case("block_count") {
            Self::ForBlockCount(parse_u64(arg)?)
        } else if lock_type.eq_ignore_ascii_case("seconds") {
            Self::ForSeconds(parse_u64(arg)?)
        } else if lock_type.eq_ignore_ascii_case("until_height") {
            Self::UntilHeight(parse_u64(arg)?.into())
        } else if lock_type.eq_ignore_ascii_case("until_time") {
            let date_time = arg
                .parse::<chrono::DateTime<chrono::Utc>>()
                .map_err(|_| ParseError::InvalidTime(arg.to_owned()))?;
            let time =
                Time::from_absolute_time(&date_time).ok_or(ParseError::BadTime(date_time))?;

            Self::UntilTime(BlockTimestamp::from_time(time))
        } else {
            return Err(ParseError::UnknownOutputTimeLockType(lock_type.to_owned()));
        };

        Ok(result)
    }
}

impl From<CliOutputTimeLock> for OutputTimeLock {
    fn from(value: CliOutputTimeLock) -> Self {
        match value {
            CliOutputTimeLock::UntilHeight(val) => OutputTimeLock::UntilHeight(val),
            CliOutputTimeLock::UntilTime(val) => OutputTimeLock::UntilTime(val),
            CliOutputTimeLock::ForBlockCount(val) => OutputTimeLock::ForBlockCount(val),
            CliOutputTimeLock::ForSeconds(val) => OutputTimeLock::ForSeconds(val),
        }
    }
}

/// Parse a decimal amount
pub fn parse_decimal_amount(input: &str) -> Result<DecimalAmount, ParseError> {
    DecimalAmount::from_str(input).map_err(|_| ParseError::InvalidDecimalAmount(input.to_owned()))
}

/// Parse a destination
pub fn parse_destination(
    chain_config: &ChainConfig,
    input: &str,
) -> Result<Destination, ParseError> {
    decode_address(chain_config, input)
        .map_err(|_| ParseError::InvalidDestination(input.to_owned()))
}

#[derive(Debug, Clone)]
pub enum CliCurrency {
    Coin,
    Token(String),
}

impl FromStr for CliCurrency {
    type Err = ParseError;

    /// Try parsing the passed input as coins (case-insensitive "coin" is accepted), otherwise
    /// treat it as a token id.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.eq_ignore_ascii_case("coin") {
            Ok(Self::Coin)
        } else {
            Ok(Self::Token(input.to_owned()))
        }
    }
}

impl CliCurrency {
    pub fn to_fully_parsed(&self, chain_config: &ChainConfig) -> Result<Currency, ParseError> {
        let result = match self {
            Self::Coin => Currency::Coin,
            Self::Token(token_id_str) => {
                let token_id = decode_address::<TokenId>(chain_config, token_id_str)
                    .map_err(|_| ParseError::InvalidCurrency(token_id_str.to_owned()))?;

                Currency::Token(token_id)
            }
        };

        Ok(result)
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliIsFreezable {
    NotFreezable,
    Freezable,
}

impl CliIsFreezable {
    pub fn to_bool(self) -> bool {
        match self {
            Self::Freezable => true,
            Self::NotFreezable => false,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliIsUnfreezable {
    NotUnfreezable,
    Unfreezable,
}

impl CliIsUnfreezable {
    pub fn to_bool(self) -> bool {
        match self {
            Self::Unfreezable => true,
            Self::NotUnfreezable => false,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliForceReduceLookaheadSize {
    IKnowWhatIAmDoing,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliYesNo {
    Yes,
    No,
}

impl CliYesNo {
    pub fn to_bool(self) -> bool {
        match self {
            Self::Yes => true,
            Self::No => false,
        }
    }
}

#[derive(thiserror::Error, Clone, Debug)]
pub enum FormatError {
    #[error("Accumulated ask amount for order {0} is negative")]
    OrderNegativeAccumulatedAskAmount(RpcAddress<OrderId>),

    #[error("Error decoding token id: {0}")]
    TokenIdDecodingError(AddressError),
}

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    #[error("Unknown source id type: {0}")]
    UnknownSourceIdType(String),

    #[error("Unknown action: {0}")]
    UnknownAction(String),

    #[error("Invalid input format")]
    InvalidInputFormat,

    #[error("Invalid token id: {0}")]
    InvalidTokenId(String),

    #[error("Invalid decimal amount: {0}")]
    InvalidDecimalAmount(String),

    #[error("Invalid number: {0}")]
    InvalidNumber(String),

    #[error("Invalid destination: {0}")]
    InvalidDestination(String),

    #[error("Invalid hash: {0}")]
    InvalidHash(String),

    #[error("Invalid output index: {0}")]
    InvalidOutputIndex(String),

    #[error("Unknown token supply type: {0}")]
    UnknownTokenSupplyType(String),

    #[error("Unknown output timelock type: {0}")]
    UnknownOutputTimeLockType(String),

    #[error("Invalid time: {0}")]
    InvalidTime(String),

    #[error("Bad time: {0}")]
    BadTime(chrono::DateTime<chrono::Utc>),

    #[error("Invalid currency: {0}")]
    InvalidCurrency(String),

    #[error("Decimal amount cannot be converted to atoms: {0}")]
    DecimalAmountNotConvertibleToAtoms(DecimalAmountWithIsSameComparison),

    #[error("Address error: {0}")]
    AddressError(#[from] AddressError),

    #[error(transparent)]
    GenericCurrencyTransferToTxOutputConversionError(
        #[from] GenericCurrencyTransferToTxOutputConversionError,
    ),
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rstest::rstest;

    use common::{
        address::pubkeyhash::PublicKeyHash,
        chain::{self, tokens::TokenId, Destination},
    };
    use randomness::Rng;
    use test_utils::{
        assert_matches, assert_matches_return_val,
        random::{make_seedable_rng, Seed},
    };
    use wallet_rpc_lib::types::RpcAmountIn;

    use super::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_parse_funclike_expr(#[case] seed: Seed) {
        use test_utils::random::{collect_string_with_random_spaces, gen_random_alnum_string};

        let mut rng = make_seedable_rng(seed);

        for _ in 0..10 {
            let args_count = rng.gen_range(1..5);
            let args = (0..args_count)
                .map(|_| gen_random_alnum_string(&mut rng, 1, 5))
                .collect::<Vec<_>>();
            let name = gen_random_alnum_string(&mut rng, 1, 5);

            let str_to_parse = collect_string_with_random_spaces(
                &mut rng,
                std::iter::once(name.as_str())
                    .chain(std::iter::once("("))
                    .chain(itertools::intersperse(args.iter().map(String::as_str), ","))
                    .chain(std::iter::once(")")),
                0,
                3,
            );

            let (parsed_name, parsed_args) = parse_funclike_expr(&str_to_parse).unwrap();
            let parsed_args = parsed_args.map(<str>::to_owned).collect::<Vec<_>>();
            assert_eq!(parsed_name, name);
            assert_eq!(parsed_args, args);

            let str_without_opening_paren = str_to_parse.replace('(', "");
            assert!(parse_funclike_expr(&str_without_opening_paren).is_none());
            let str_without_closing_paren = str_to_parse.replace(')', "");
            assert!(parse_funclike_expr(&str_without_closing_paren).is_none());
            let str_without_paren = str_without_opening_paren.replace(')', "");
            assert!(parse_funclike_expr(&str_without_paren).is_none());

            let str_to_parse = collect_string_with_random_spaces(
                &mut rng,
                std::iter::once(name.as_str())
                    .chain(std::iter::once("("))
                    .chain(std::iter::once(")")),
                0,
                3,
            );

            let (parsed_name, parsed_args) = parse_funclike_expr(&str_to_parse).unwrap();
            let parsed_args = parsed_args.map(<str>::to_owned).collect::<Vec<_>>();
            assert_eq!(parsed_name, name);
            assert_eq!(parsed_args, vec![""]);

            let str_without_opening_paren = str_to_parse.replace('(', "");
            assert!(parse_funclike_expr(&str_without_opening_paren).is_none());
            let str_without_closing_paren = str_to_parse.replace(')', "");
            assert!(parse_funclike_expr(&str_without_closing_paren).is_none());
            let str_without_paren = str_without_opening_paren.replace(')', "");
            assert!(parse_funclike_expr(&str_without_paren).is_none());
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_parse_utxo_outpoint(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        for _ in 0..10 {
            let h256 = H256::random_using(&mut rng);
            let idx = rng.gen::<u32>();

            for tag in ["tx", "Tx", "tX"] {
                let parsed_outpoint: UtxoOutPoint =
                    CliUtxoOutPoint::from_str(&format!("{tag}({h256:x},{idx})")).unwrap().into();
                assert_eq!(
                    parsed_outpoint,
                    UtxoOutPoint::new(OutPointSourceId::Transaction(h256.into()), idx)
                );
            }

            for tag in ["block", "Block", "bLOck"] {
                let parsed_outpoint: UtxoOutPoint =
                    CliUtxoOutPoint::from_str(&format!("{tag}({h256:x},{idx})")).unwrap().into();
                assert_eq!(
                    parsed_outpoint,
                    UtxoOutPoint::new(OutPointSourceId::BlockReward(h256.into()), idx)
                );
            }

            let err = CliUtxoOutPoint::from_str(&format!("foo({h256:x},{idx})")).unwrap_err();
            assert_eq!(err, ParseError::UnknownSourceIdType("foo".to_owned()));

            let tag = if rng.gen_bool(0.5) { "tx" } else { "block" };
            // Sanity check
            CliUtxoOutPoint::from_str(&format!("{tag}({h256:x},{idx})")).unwrap();

            let err = CliUtxoOutPoint::from_str(&format!("{tag} {h256:x},{idx})")).unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let err = CliUtxoOutPoint::from_str(&format!("{tag}({h256:x},{idx}")).unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let err = CliUtxoOutPoint::from_str(&format!("{tag} {h256:x},{idx}")).unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let err = CliUtxoOutPoint::from_str(&format!("{tag}({h256:x})")).unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let err = CliUtxoOutPoint::from_str(&format!("{tag}()")).unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_parse_unspecified_currency_transfer(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let chain_config = chain::config::create_unit_test_config();

        for _ in 0..10 {
            let pkh = PublicKeyHash::random_using(&mut rng);
            let addr = Address::new(&chain_config, Destination::PublicKeyHash(pkh)).unwrap();
            let amount = DecimalAmount::from_uint_decimal(
                rng.gen_range(0..=u128::MAX),
                rng.gen_range(0..=u8::MAX),
            );

            for tag in ["transfer", "Transfer", "traNSfer"] {
                let GenericCurrencyTransfer {
                    amount: parsed_amount,
                    destination: parsed_dest,
                } = CliUnspecifiedCurrencyTransfer::from_str(&format!("{tag}({addr},{amount})"))
                    .unwrap()
                    .to_fully_parsed(&chain_config)
                    .unwrap();

                assert_eq!(parsed_amount.mantissa(), amount.mantissa());
                assert_eq!(parsed_amount.decimals(), amount.decimals());
                assert_eq!(parsed_dest, *addr.as_object());
            }

            let err = CliUnspecifiedCurrencyTransfer::from_str(&format!("foo({addr},{amount})"))
                .unwrap_err();
            assert_eq!(err, ParseError::UnknownAction("foo".to_owned()));

            let err =
                CliUnspecifiedCurrencyTransfer::from_str(&format!("transfer {addr},{amount})"))
                    .unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let err =
                CliUnspecifiedCurrencyTransfer::from_str(&format!("transfer({addr},{amount}"))
                    .unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let err =
                CliUnspecifiedCurrencyTransfer::from_str(&format!("transfer {addr},{amount}"))
                    .unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let err =
                CliUnspecifiedCurrencyTransfer::from_str(&format!("transfer({addr})")).unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let err = CliUnspecifiedCurrencyTransfer::from_str("transfer()").unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let err = CliUnspecifiedCurrencyTransfer::from_str(&format!("transfer({addr},foo)"))
                .unwrap_err();
            assert_eq!(err, ParseError::InvalidDecimalAmount("foo".to_owned()));

            let err = CliUnspecifiedCurrencyTransfer::from_str(&format!("transfer(foo,{amount})"))
                .unwrap()
                .to_fully_parsed(&chain_config)
                .unwrap_err();
            assert_eq!(err, ParseError::InvalidDestination("foo".to_owned()));
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_parse_token_transfer(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let chain_config = chain::config::create_unit_test_config();

        for _ in 0..10 {
            let token_id = TokenId::new(H256::random_using(&mut rng));
            let token_id_as_addr = Address::new(&chain_config, token_id).unwrap();
            let pkh = PublicKeyHash::random_using(&mut rng);
            let addr = Address::new(&chain_config, Destination::PublicKeyHash(pkh)).unwrap();
            let amount = DecimalAmount::from_uint_decimal(
                rng.gen_range(0..=u128::MAX),
                rng.gen_range(0..=u8::MAX),
            );

            for tag in ["transfer", "Transfer", "traNSfer"] {
                let GenericTokenTransfer {
                    token_id: parsed_token_id,
                    amount: parsed_amount,
                    destination: parsed_dest,
                } = CliTokenTransfer::from_str(&format!(
                    "{tag}({token_id_as_addr},{addr},{amount})"
                ))
                .unwrap()
                .to_fully_parsed(&chain_config)
                .unwrap();

                assert_eq!(parsed_token_id, token_id);

                assert_eq!(parsed_amount.mantissa(), amount.mantissa());
                assert_eq!(parsed_amount.decimals(), amount.decimals());
                assert_eq!(parsed_dest, *addr.as_object());
            }

            let err =
                CliTokenTransfer::from_str(&format!("foo({token_id_as_addr},{addr},{amount})"))
                    .unwrap_err();
            assert_eq!(err, ParseError::UnknownAction("foo".to_owned()));

            let err = CliTokenTransfer::from_str(&format!(
                "transfer {token_id_as_addr},{addr},{amount})"
            ))
            .unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let err =
                CliTokenTransfer::from_str(&format!("transfer({token_id_as_addr},{addr},{amount}"))
                    .unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let err =
                CliTokenTransfer::from_str(&format!("transfer {token_id_as_addr},{addr},{amount}"))
                    .unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let err = CliTokenTransfer::from_str(&format!("transfer({token_id_as_addr},{addr})"))
                .unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let err =
                CliTokenTransfer::from_str(&format!("transfer({token_id_as_addr})")).unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let err = CliTokenTransfer::from_str("transfer()").unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let err =
                CliTokenTransfer::from_str(&format!("transfer({token_id_as_addr},{addr},foo)"))
                    .unwrap_err();
            assert_eq!(err, ParseError::InvalidDecimalAmount("foo".to_owned()));

            let err = CliTokenTransfer::from_str(&format!("transfer(foo,{addr},{amount})"))
                .unwrap()
                .to_fully_parsed(&chain_config)
                .unwrap_err();
            assert_eq!(err, ParseError::InvalidTokenId("foo".to_owned()));

            let err =
                CliTokenTransfer::from_str(&format!("transfer({token_id_as_addr},foo,{amount})"))
                    .unwrap()
                    .to_fully_parsed(&chain_config)
                    .unwrap_err();
            assert_eq!(err, ParseError::InvalidDestination("foo".to_owned()));
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_parse_token_total_supply(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        for _ in 0..10 {
            let token_number_of_decimals = rng.gen_range(0..20);

            for tag in ["unlimited", "Unlimited", "unLImited"] {
                let parsed_supply = CliTokenTotalSupply::from_str(tag)
                    .unwrap()
                    .to_fully_parsed(token_number_of_decimals)
                    .unwrap();
                assert_matches!(parsed_supply, TokenTotalSupply::Unlimited);
            }

            for tag in ["lockable", "Lockable", "locKAble"] {
                let parsed_supply = CliTokenTotalSupply::from_str(tag)
                    .unwrap()
                    .to_fully_parsed(token_number_of_decimals)
                    .unwrap();
                assert_matches!(parsed_supply, TokenTotalSupply::Lockable);
            }

            let decimal_amount = DecimalAmount::from_uint_decimal(
                rng.gen_range(0..=1_000_000_000_000),
                rng.gen_range(0..=token_number_of_decimals),
            );

            for tag in ["fixed", "Fixed", "fIXed"] {
                let parsed_supply =
                    CliTokenTotalSupply::from_str(&format!("{tag}({decimal_amount})"))
                        .unwrap()
                        .to_fully_parsed(token_number_of_decimals)
                        .unwrap();
                let parsed_amount = assert_matches_return_val!(
                    parsed_supply,
                    TokenTotalSupply::Fixed(amount),
                    amount
                );
                let expected_atoms = decimal_amount.to_amount(token_number_of_decimals).unwrap();
                assert!(parsed_amount.is_same(&RpcAmountIn::from_atoms(expected_atoms)));
            }

            let err = CliTokenTotalSupply::from_str("foo").unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let err = CliTokenTotalSupply::from_str("fixed").unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let err = CliTokenTotalSupply::from_str(&format!("foo({decimal_amount})")).unwrap_err();
            assert_eq!(err, ParseError::UnknownTokenSupplyType("foo".to_owned()));

            let err = CliTokenTotalSupply::from_str("fixed()").unwrap_err();
            assert_eq!(err, ParseError::InvalidDecimalAmount("".to_owned()));

            let err =
                CliTokenTotalSupply::from_str(&format!("fixed({decimal_amount},{decimal_amount})"))
                    .unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let err =
                CliTokenTotalSupply::from_str(&format!("fixed {decimal_amount})")).unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let err =
                CliTokenTotalSupply::from_str(&format!("fixed({decimal_amount}")).unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let decimal_amount_with_too_many_decimals = {
                let mut mantissa = rng.gen_range(0..=1_000_000_000_000);
                // Make sure that the number has indeed more decimals than `token_number_of_decimals`.
                if mantissa % 10 == 0 {
                    mantissa += rng.gen_range(1..=9);
                }
                DecimalAmount::from_uint_decimal(mantissa, token_number_of_decimals + 1)
            };

            let err = CliTokenTotalSupply::from_str(&format!(
                "fixed({decimal_amount_with_too_many_decimals})",
            ))
            .unwrap()
            .to_fully_parsed(token_number_of_decimals)
            .unwrap_err();
            assert_eq!(
                err,
                ParseError::DecimalAmountNotConvertibleToAtoms(
                    decimal_amount_with_too_many_decimals.into()
                )
            );
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_parse_output_timelock(#[case] seed: Seed) {
        use chrono::prelude::*;

        let mut rng = make_seedable_rng(seed);

        for _ in 0..10 {
            let u64_val = rng.gen::<u64>();

            for tag in ["block_count", "Block_count", "blocK_Count"] {
                let parsed_timelock: OutputTimeLock =
                    CliOutputTimeLock::from_str(&format!("{tag}({u64_val})")).unwrap().into();
                assert_eq!(parsed_timelock, OutputTimeLock::ForBlockCount(u64_val));
            }

            for tag in ["seconds", "Seconds", "secONds"] {
                let parsed_timelock: OutputTimeLock =
                    CliOutputTimeLock::from_str(&format!("{tag}({u64_val})")).unwrap().into();
                assert_eq!(parsed_timelock, OutputTimeLock::ForSeconds(u64_val));
            }

            for tag in ["until_height", "Until_height", "until_HEight"] {
                let parsed_timelock: OutputTimeLock =
                    CliOutputTimeLock::from_str(&format!("{tag}({u64_val})")).unwrap().into();
                assert_eq!(parsed_timelock, OutputTimeLock::UntilHeight(u64_val.into()));
            }

            let year = rng.gen_range(1970..=3000);
            let month = rng.gen_range(1..=12);
            let days_in_month =
                NaiveDate::from_ymd_opt(year, month, 1).unwrap().num_days_in_month();
            let day = rng.gen_range(1..=days_in_month);
            let hour = rng.gen_range(0..24);
            let min = rng.gen_range(0..60);
            let sec = rng.gen_range(0..60);
            let expected_time = NaiveDateTime::new(
                NaiveDate::from_ymd_opt(year, month, day.into()).unwrap(),
                NaiveTime::from_hms_opt(hour, min, sec).unwrap(),
            );
            let expected_time_utc = DateTime::from_naive_utc_and_offset(expected_time, Utc);
            let tz_hours = rng.gen_range(0..24);
            let tz_mins = rng.gen_range(0..60);
            let tz_positive = rng.gen_bool(0.5);
            let expected_time_with_tz = {
                let offset = Duration::from_secs(tz_hours * 3600 + tz_mins * 60);
                if tz_positive {
                    expected_time_utc - offset
                } else {
                    expected_time_utc + offset
                }
            };
            let datetime_base_str = format!("{year}-{month}-{day}T{hour}:{min}:{sec}");
            let datetime_str_utc = format!("{datetime_base_str}Z");
            let tz_plus_minus = if tz_positive { "+" } else { "-" };
            let tz_str = format!("{tz_plus_minus}{tz_hours:02}:{tz_mins:02}");

            for tag in ["until_time", "Until_time", "untIL_time"] {
                let parsed_timelock: OutputTimeLock =
                    CliOutputTimeLock::from_str(&format!("{tag}({datetime_str_utc})"))
                        .unwrap()
                        .into();

                assert_eq!(
                    parsed_timelock,
                    OutputTimeLock::UntilTime(BlockTimestamp::from_time(
                        Time::from_absolute_time(&expected_time_utc).unwrap()
                    ))
                );

                let parsed_timelock: OutputTimeLock =
                    CliOutputTimeLock::from_str(&format!("{tag}({datetime_base_str}{tz_str})"))
                        .unwrap()
                        .into();

                assert_eq!(
                    parsed_timelock,
                    OutputTimeLock::UntilTime(BlockTimestamp::from_time(
                        Time::from_absolute_time(&expected_time_with_tz).unwrap()
                    ))
                );
            }

            let sec_frac = rng.gen_range(1..1000);
            let err = CliOutputTimeLock::from_str(&format!(
                "until_time({datetime_base_str}.{sec_frac}Z)"
            ))
            .unwrap_err();
            assert_matches!(err, ParseError::BadTime(_));

            let err = CliOutputTimeLock::from_str("foo").unwrap_err();
            assert_eq!(err, ParseError::InvalidInputFormat);

            let err = CliOutputTimeLock::from_str(&format!("foo({u64_val})")).unwrap_err();
            assert_eq!(err, ParseError::UnknownOutputTimeLockType("foo".to_owned()));

            for (valid_tag, is_date) in [
                ("block_count", false),
                ("seconds", false),
                ("until_height", false),
                ("until_time", true),
            ] {
                let arg = if is_date {
                    datetime_str_utc.clone()
                } else {
                    u64_val.to_string()
                };

                // Sanity check
                CliOutputTimeLock::from_str(&format!("{valid_tag}({arg})")).unwrap();

                let err = CliOutputTimeLock::from_str(valid_tag).unwrap_err();
                assert_eq!(err, ParseError::InvalidInputFormat);

                let err = CliOutputTimeLock::from_str(&format!("{valid_tag}()")).unwrap_err();
                if is_date {
                    assert_eq!(err, ParseError::InvalidTime("".to_owned()));
                } else {
                    assert_eq!(err, ParseError::InvalidNumber("".to_owned()));
                };

                let err =
                    CliOutputTimeLock::from_str(&format!("{valid_tag}({arg},{arg})")).unwrap_err();
                assert_eq!(err, ParseError::InvalidInputFormat);

                let err = CliOutputTimeLock::from_str(&format!("{valid_tag}({arg}")).unwrap_err();
                assert_eq!(err, ParseError::InvalidInputFormat);

                let err = CliOutputTimeLock::from_str(&format!("{valid_tag} {arg})")).unwrap_err();
                assert_eq!(err, ParseError::InvalidInputFormat);
            }
        }
    }

    #[test]
    fn test_parse_currency() {
        let chain_config = chain::config::create_unit_test_config();

        let currency =
            CliCurrency::from_str("coin").unwrap().to_fully_parsed(&chain_config).unwrap();
        assert_eq!(currency, Currency::Coin);
        let currency =
            CliCurrency::from_str("cOiN").unwrap().to_fully_parsed(&chain_config).unwrap();
        assert_eq!(currency, Currency::Coin);

        let err = CliCurrency::from_str("coins")
            .unwrap()
            .to_fully_parsed(&chain_config)
            .unwrap_err();
        assert_eq!(err, ParseError::InvalidCurrency("coins".to_owned()));

        let currency = CliCurrency::from_str(
            "rmltk1ktt2slkqdy607kzhueudqucqphjzl7kl506xf78f9w7v00ydythqzgwlyp",
        )
        .unwrap()
        .to_fully_parsed(&chain_config)
        .unwrap();
        assert_eq!(
            currency,
            Currency::Token(TokenId::new(
                H256::from_str("b2d6a87ec06934ff5857e678d073000de42ffadfa3f464f8e92bbcc7bc8d22ee")
                    .unwrap()
            ))
        );

        let bad_token_id = "rpool1zg7yccqqjlz38cyghxlxyp5lp36vwecu2g7gudrf58plzjm75tzq99fr6v";
        let err = CliCurrency::from_str(bad_token_id)
            .unwrap()
            .to_fully_parsed(&chain_config)
            .unwrap_err();
        assert_eq!(err, ParseError::InvalidCurrency(bad_token_id.to_owned()));
    }
}
