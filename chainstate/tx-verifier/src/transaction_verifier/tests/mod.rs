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
mod hierarchy_utxo_undo;
mod hierarchy_write;
mod mock;

use super::*;
use common::{
    chain::{
        output_value::OutputValue, stakelock::StakePoolData, Destination, OutPointSourceId,
        UtxoOutPoint,
    },
    primitives::{amount::UnsignedIntType, per_thousand::PerThousand, BlockHeight, H256},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    random::{CryptoRng, Rng},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use utxo::Utxo;

fn create_utxo(rng: &mut (impl Rng + CryptoRng), value: UnsignedIntType) -> (UtxoOutPoint, Utxo) {
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

fn new_pub_key_destination(rng: &mut (impl Rng + CryptoRng)) -> Destination {
    let (_, pub_key) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    Destination::PublicKey(pub_key)
}

fn create_pool_data(
    rng: &mut (impl Rng + CryptoRng),
    staker: Destination,
    decommission_destination: Destination,
    pledged_amount: Amount,
) -> StakePoolData {
    let (_, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
    let margin_ratio = PerThousand::new_from_rng(rng);
    let cost_per_block = Amount::from_atoms(rng.gen_range(0..1000));
    StakePoolData::new(
        pledged_amount,
        staker,
        vrf_pk,
        decommission_destination,
        margin_ratio,
        cost_per_block,
    )
}
