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

mod hierarchy_read;
mod hierarchy_write;
pub mod mock;

use super::*;
use common::{
    chain::{
        Destination, OutPointSourceId, UtxoOutPoint, config::Builder as ConfigBuilder,
        output_value::OutputValue, stakelock::StakePoolData,
    },
    primitives::{BlockHeight, H256, amount::UnsignedIntType, per_thousand::PerThousand},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use randomness::{CryptoRng, RngExt as _};
use utxo::Utxo;

pub fn create_utxo(rng: &mut impl CryptoRng, value: UnsignedIntType) -> (UtxoOutPoint, Utxo) {
    let outpoint = UtxoOutPoint::new(
        OutPointSourceId::Transaction(Id::new(H256::random_using(rng))),
        0,
    );
    let (_, pub_key1) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let output1 = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(value)),
        Destination::PublicKey(pub_key1),
    );
    let utxo = Utxo::new_for_blockchain(output1, BlockHeight::new(1));
    (outpoint, utxo)
}

fn new_pub_key_destination(rng: &mut impl CryptoRng) -> Destination {
    let (_, pub_key) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    Destination::PublicKey(pub_key)
}

fn create_pool_data(
    rng: &mut impl CryptoRng,
    staker: Destination,
    decommission_destination: Destination,
    pledged_amount: Amount,
) -> StakePoolData {
    let (_, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
    let margin_ratio = PerThousand::new_from_rng(rng);
    let cost_per_block = Amount::from_atoms(rng.random_range(0..1000));
    StakePoolData::new(
        pledged_amount,
        staker,
        vrf_pk,
        decommission_destination,
        margin_ratio,
        cost_per_block,
    )
}

// DEX trade matches left in the verifier when it is consumed are dropped, which is reported as a
// broken invariant: a panic in debug builds, an error log in release builds.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "DEX trade match(es) left untaken before consuming the verifier")]
fn untaken_dex_trade_matches_are_reported_when_consuming() {
    let chain_config = ConfigBuilder::test_chain().build();
    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    let mut verifier = TransactionVerifier::new(&store, &chain_config);
    verifier.dex_trade_matches.push(untaken_dex_trade_match());
    verifier.consume().unwrap();
}

#[cfg(not(debug_assertions))]
#[test]
fn untaken_dex_trade_matches_are_reported_when_consuming() {
    let chain_config = ConfigBuilder::test_chain().build();
    let mut store = mock::MockStore::new();
    store.expect_get_best_block_for_utxos().return_const(Ok(H256::zero().into()));
    let mut verifier = TransactionVerifier::new(&store, &chain_config);
    verifier.dex_trade_matches.push(untaken_dex_trade_match());
    // the matches are dropped and the state is consumed regardless
    verifier.consume().unwrap();
}

/// A DEX trade match, as recorded by [`TransactionVerifier::fill_order`].
fn untaken_dex_trade_match() -> DexTradeMatch {
    DexTradeMatch {
        tx_id: Id::new(H256::zero()),
        input_ordinal: 0,
        match_ordinal: 0,
        maker_order_id: OrderId::zero(),
        base: Currency::Coin,
        quote: Currency::Coin,
        base_amount: Amount::from_atoms(1),
        quote_amount: Amount::from_atoms(1),
    }
}
