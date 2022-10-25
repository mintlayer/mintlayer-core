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
mod mock;

use super::*;
use common::{
    chain::{Destination, OutPoint, OutputPurpose},
    primitives::{amount::UnsignedIntType, H256},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    random::Rng,
};

fn create_utxo(rng: &mut impl Rng, value: UnsignedIntType) -> (OutPoint, Utxo) {
    let outpoint = OutPoint::new(
        OutPointSourceId::Transaction(Id::new(H256::random_using(rng))),
        0,
    );
    let (_, pub_key1) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let output1 = TxOutput::new(
        OutputValue::Coin(Amount::from_atoms(value)),
        OutputPurpose::Transfer(Destination::PublicKey(pub_key1)),
    );
    let utxo = Utxo::new_for_blockchain(output1, false, BlockHeight::new(1));
    (outpoint, utxo)
}
