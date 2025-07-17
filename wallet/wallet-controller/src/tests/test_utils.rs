// Copyright (c) 2021-2025 RBB S.r.l
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

use std::collections::BTreeMap;

use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        block::{BlockReward, ConsensusData},
        output_value::OutputValue,
        tokens::{
            IsTokenFreezable, IsTokenUnfreezable, Metadata, NftIssuance, NftIssuanceV0,
            RPCFungibleTokenInfo, RPCIsTokenFrozen, RPCTokenTotalSupply, TokenCreator, TokenId,
            TokenTotalSupply,
        },
        Block, ChainConfig, Destination, OrderId, SignedTransaction, Transaction, TxOutput,
    },
    primitives::{amount::RpcAmountOut, Amount, BlockHeight},
};
use crypto::{
    key::{KeyKind, PrivateKey, PublicKey},
    vrf::{VRFKeyKind, VRFPrivateKey, VRFPublicKey},
};
use randomness::{CryptoRng, Rng};
use test_utils::random::{gen_random_alnum_string, gen_random_bytes};
use wallet::{signer::SignerProvider, wallet::test_helpers::scan_wallet, DefaultWallet, Wallet};
use wallet_types::{account_info::DEFAULT_ACCOUNT_INDEX, Currency};

use crate::types::Balances;

pub fn assert_fees(
    actual_fees: &Balances,
    expected_coin_fee: Amount,
    expected_token_fees: &BTreeMap<TokenId, Amount>,
    token_decimals: &BTreeMap<TokenId, u8>,
    chain_config: &ChainConfig,
) {
    assert_eq!(actual_fees.coins().amount(), expected_coin_fee);
    assert_consistent_rpc_amount_out(actual_fees.coins(), chain_config.coin_decimals());

    let actual_token_fees = actual_fees
        .tokens()
        .iter()
        .map(|(token_id_addr, amount_out)| {
            let token_id = token_id_addr.decode_object(chain_config).unwrap();
            let token_decimals = token_decimals.get(&token_id);
            assert!(
                token_decimals.is_some(),
                "decimals for token {token_id:x} not provided"
            );
            assert_consistent_rpc_amount_out(amount_out, *token_decimals.unwrap());
            (token_id, amount_out.amount())
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(&actual_token_fees, expected_token_fees);
}

pub fn assert_consistent_rpc_amount_out(amount_out: &RpcAmountOut, decimals: u8) {
    assert_eq!(
        amount_out.decimal().to_amount(decimals).unwrap(),
        amount_out.amount()
    );
}

pub fn random_rpc_ft_info_with_id_ticker_decimals(
    id: TokenId,
    ticker: String,
    num_decimals: u8,
    rng: &mut impl Rng,
) -> RPCFungibleTokenInfo {
    RPCFungibleTokenInfo {
        token_id: id,
        token_ticker: ticker.into(),
        number_of_decimals: num_decimals,
        metadata_uri: gen_random_alnum_string(rng, 10, 20).into(),
        circulating_supply: Amount::from_atoms(rng.gen()),
        total_supply: RPCTokenTotalSupply::Unlimited,
        is_locked: rng.gen_bool(0.5),
        frozen: random_rpc_is_token_frozen(rng),
        authority: Destination::PublicKeyHash(PublicKeyHash::random_using(rng)),
    }
}

pub fn random_rpc_is_token_frozen(rng: &mut impl Rng) -> RPCIsTokenFrozen {
    if rng.gen_bool(0.5) {
        RPCIsTokenFrozen::NotFrozen {
            freezable: rng.gen(),
        }
    } else {
        RPCIsTokenFrozen::Frozen {
            unfreezable: rng.gen(),
        }
    }
}

pub fn random_is_token_freezable(rng: &mut impl Rng) -> IsTokenFreezable {
    if rng.gen_bool(0.5) {
        IsTokenFreezable::Yes
    } else {
        IsTokenFreezable::No
    }
}

pub fn random_is_token_unfreezable(rng: &mut impl Rng) -> IsTokenUnfreezable {
    if rng.gen_bool(0.5) {
        IsTokenUnfreezable::Yes
    } else {
        IsTokenUnfreezable::No
    }
}

pub fn random_token_total_supply(rng: &mut impl Rng) -> TokenTotalSupply {
    match rng.gen_range(0..3) {
        0 => TokenTotalSupply::Fixed(Amount::from_atoms(rng.gen())),
        1 => TokenTotalSupply::Lockable,
        _ => TokenTotalSupply::Unlimited,
    }
}

pub fn random_nft_issuance(rng: &mut (impl Rng + CryptoRng)) -> NftIssuance {
    NftIssuance::V0(NftIssuanceV0 {
        metadata: Metadata {
            creator: Some(TokenCreator {
                public_key: random_pub_key(rng),
            }),
            name: gen_random_alnum_string(rng, 10, 20).into_bytes(),
            description: gen_random_alnum_string(rng, 10, 20).into_bytes(),
            ticker: gen_random_alnum_string(rng, 10, 20).into_bytes(),
            icon_uri: Some(gen_random_alnum_string(rng, 10, 20).into_bytes()).into(),
            additional_metadata_uri: Some(gen_random_alnum_string(rng, 10, 20).into_bytes()).into(),
            media_uri: Some(gen_random_alnum_string(rng, 10, 20).into_bytes()).into(),
            media_hash: gen_random_bytes(rng, 10, 20),
        },
    })
}

pub fn wallet_new_dest(wallet: &mut DefaultWallet) -> Destination {
    wallet.get_new_address(DEFAULT_ACCOUNT_INDEX).unwrap().1.into_object()
}

pub fn random_pub_key(rng: &mut (impl Rng + CryptoRng)) -> PublicKey {
    PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr).1
}

pub fn random_vrf_pub_key(rng: &mut (impl Rng + CryptoRng)) -> VRFPublicKey {
    VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel).1
}

pub fn tx_with_outputs(outputs: Vec<TxOutput>) -> SignedTransaction {
    SignedTransaction::new(Transaction::new(0, vec![], outputs).unwrap(), Vec::new()).unwrap()
}

pub fn create_block_scan_wallet<B, P>(
    chain_config: &ChainConfig,
    wallet: &mut Wallet<B, P>,
    transactions: Vec<SignedTransaction>,
    reward: Amount,
    reward_dest: Destination,
    block_height: u64,
) -> Block
where
    B: storage::Backend + 'static,
    P: SignerProvider,
{
    let block = Block::new(
        transactions,
        chain_config.genesis_block_id(),
        chain_config.genesis_block().timestamp(),
        ConsensusData::None,
        BlockReward::new(vec![TxOutput::Transfer(
            OutputValue::Coin(reward),
            reward_dest,
        )]),
    )
    .unwrap();

    scan_wallet(wallet, BlockHeight::new(block_height), vec![block.clone()]);
    block
}

pub const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

pub struct TestTokenData {
    pub id: TokenId,
    pub num_decimals: u8,
    pub ticker: String,
    pub metadata_uri: String,
    pub total_supply: TokenTotalSupply,
    pub authority: Destination,
    pub is_freezable: IsTokenFreezable,
}

pub fn random_token_data_with_id_and_authority(
    token_id: TokenId,
    authority: Destination,
    rng: &mut impl Rng,
) -> TestTokenData {
    TestTokenData {
        id: token_id,
        num_decimals: rng.gen_range(1..20),
        ticker: gen_random_alnum_string(rng, 5, 10),
        metadata_uri: gen_random_alnum_string(rng, 5, 10),
        total_supply: random_token_total_supply(rng),
        authority,
        is_freezable: random_is_token_freezable(rng),
    }
}

pub struct TestOrderData {
    pub id: OrderId,
    pub initially_asked: OutputValue,
    pub initially_given: OutputValue,
    pub ask_balance: Amount,
    pub give_balance: Amount,
    pub conclude_key: Destination,
}

pub struct OrderCurrencies {
    pub ask: Currency,
    pub give: Currency,
}

pub fn random_order_currencies_with_token(
    rng: &mut impl Rng,
    token_id: TokenId,
) -> OrderCurrencies {
    if rng.gen_bool(0.5) {
        OrderCurrencies {
            ask: Currency::Coin,
            give: Currency::Token(token_id),
        }
    } else {
        OrderCurrencies {
            ask: Currency::Token(token_id),
            give: Currency::Coin,
        }
    }
}
