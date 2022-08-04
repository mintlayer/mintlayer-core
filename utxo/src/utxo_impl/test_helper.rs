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

use crate::{Utxo, UtxoEntry, UtxosCache};
use common::chain::signature::inputsig::InputWitness;
use common::chain::tokens::OutputValue;
use common::chain::{
    Destination, GenBlock, OutPoint, OutPointSourceId, OutputPurpose, Transaction, TxInput,
    TxOutput,
};
use common::primitives::{Amount, BlockHeight, Id, H256};
use crypto::key::{KeyKind, PrivateKey};
use crypto::random::{make_pseudo_rng, seq, Rng};
use itertools::Itertools;

pub const FRESH: u8 = 1;
pub const DIRTY: u8 = 2;

#[derive(Clone, Eq, PartialEq)]
pub enum Presence {
    Absent,
    Present,
    Spent,
}

use crate::UtxoStatus;
use Presence::{Absent, Present, Spent};

pub fn create_tx_outputs(size: u32) -> Vec<TxOutput> {
    let mut tx_outputs = vec![];
    for _ in 0..size {
        let random_amt = make_pseudo_rng().gen_range(1..u128::MAX);
        let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        tx_outputs.push(TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(random_amt)),
            OutputPurpose::Transfer(Destination::PublicKey(pub_key)),
        ));
    }

    tx_outputs
}

/// randomly select half of the provided outpoints to spend, and returns it in a vec of structure of TxInput
pub fn create_tx_inputs(outpoints: &[OutPoint]) -> Vec<TxInput> {
    let mut rng = make_pseudo_rng();
    let to_spend = seq::index::sample(&mut rng, outpoints.len(), outpoints.len() / 2).into_vec();
    to_spend
        .into_iter()
        .map(|idx| {
            let outpoint = outpoints.get(idx).expect("should return an outpoint");
            TxInput::new(
                outpoint.tx_id(),
                outpoint.output_index(),
                InputWitness::NoSignature(None),
            )
        })
        .collect_vec()
}

/// converts the given parameters into the tuple (Outpoint, Utxo).
pub fn convert_to_utxo(output: TxOutput, height: u64, output_idx: usize) -> (OutPoint, Utxo) {
    let utxo_id: Id<GenBlock> = Id::new(H256::random());
    let id = OutPointSourceId::BlockReward(utxo_id);
    let outpoint = OutPoint::new(id, output_idx as u32);
    let utxo = Utxo::new(output, true, BlockHeight::new(height));

    (outpoint, utxo)
}

pub fn create_utxo(block_height: u64) -> (Utxo, OutPoint) {
    inner_create_utxo(Some(block_height))
}

pub fn create_utxo_for_mempool() -> (Utxo, OutPoint) {
    inner_create_utxo(None)
}

/// returns a tuple of utxo and outpoint, for testing.
fn inner_create_utxo(block_height: Option<u64>) -> (Utxo, OutPoint) {
    // just a random value generated, and also a random `is_block_reward` value.
    let rng = make_pseudo_rng().gen_range(0..u128::MAX);
    let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let output = TxOutput::new(
        OutputValue::Coin(Amount::from_atoms(rng)),
        OutputPurpose::Transfer(Destination::PublicKey(pub_key)),
    );
    let is_block_reward = rng % 3 == 0;

    // generate utxo
    let utxo = match block_height {
        None => Utxo::new_for_mempool(output, is_block_reward),
        Some(height) => Utxo::new(output, is_block_reward, BlockHeight::new(height)),
    };

    // create the id based on the `is_block_reward` value.
    let id = {
        if !is_block_reward {
            let utxo_id: Id<Transaction> = Id::new(H256::random());
            OutPointSourceId::Transaction(utxo_id)
        } else {
            let utxo_id: Id<GenBlock> = Id::new(H256::random());
            OutPointSourceId::BlockReward(utxo_id)
        }
    };

    let outpoint = OutPoint::new(id, 0);

    (utxo, outpoint)
}

/// inserts a random utxo in the cache.
/// returns the utxo and the outpoint.
/// # Arguments
/// `cache` - a mutable reference of the UtxosCache
/// `cache_presence` - sets the initial state of the cache.
/// `cache_flags` - sets the entry of the utxo (fresh/not, dirty/not)
/// `outpoint` - optional key to be used, rather than a randomly generated one.
pub fn insert_single_entry(
    cache: &mut UtxosCache,
    cache_presence: &Presence,
    cache_flags: Option<u8>,
    outpoint: Option<OutPoint>,
) -> (Utxo, OutPoint) {
    let rng_height = make_pseudo_rng().gen_range(0..(u64::MAX - 1));
    let (utxo, outpoint_x) = create_utxo(rng_height);
    let outpoint = outpoint.unwrap_or(outpoint_x);
    let key = &outpoint;

    match cache_presence {
        Absent => {
            // there shouldn't be an existing entry. Don't bother with the cache flags.
        }
        other => {
            let flags = cache_flags.expect("please provide flags.");
            let is_dirty = (flags & DIRTY) == DIRTY;
            let is_fresh = (flags & FRESH) == FRESH;

            let entry = match other {
                Present => UtxoEntry::new(utxo.clone(), is_fresh, is_dirty),
                Spent => UtxoEntry {
                    status: UtxoStatus::Spent,
                    is_dirty,
                    is_fresh,
                },
                _ => {
                    panic!("something wrong in the code.")
                }
            };

            // let's insert an entry.
            cache.utxos.insert(key.clone(), entry);
        }
    }

    (utxo, outpoint)
}

/// checks the dirty, fresh, and spent flags.
pub(crate) fn check_flags(
    result_entry: Option<&UtxoEntry>,
    expected_flags: Option<u8>,
    is_spent: bool,
) {
    if let Some(flags) = expected_flags {
        let result_entry = result_entry.expect("this should have an entry inside");

        assert_eq!(result_entry.is_dirty(), (flags & DIRTY) == DIRTY);
        assert_eq!(result_entry.is_fresh(), (flags & FRESH) == FRESH);
        assert_eq!(result_entry.is_spent(), is_spent);
    } else {
        assert!(result_entry.is_none());
    }
}
