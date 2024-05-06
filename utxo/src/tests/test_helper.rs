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

use std::convert::Infallible;

use crate::{
    utxo_entry::{IsDirty, IsFresh, UtxoEntry},
    Utxo, UtxosCache, UtxosView,
};
use common::{
    chain::{
        output_value::OutputValue, Destination, GenBlock, OutPointSourceId, Transaction, TxInput,
        TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id, H256},
};
use crypto::key::{KeyKind, PrivateKey};
use itertools::Itertools;
use randomness::{seq, CryptoRng, Rng};

pub trait UnwrapInfallible {
    type Output;
    fn unwrap_infallible(self) -> Self::Output;
}

impl<T> UnwrapInfallible for Result<T, Infallible> {
    type Output = T;
    fn unwrap_infallible(self) -> Self::Output {
        self.unwrap_or_else(|inf| match inf {})
    }
}

struct EmptyUtxosView {
    best_block_hash: Id<GenBlock>,
}

impl UtxosView for EmptyUtxosView {
    type Error = Infallible;

    fn utxo(&self, _outpoint: &UtxoOutPoint) -> Result<Option<Utxo>, Infallible> {
        Ok(None)
    }

    fn has_utxo(&self, _outpoint: &UtxoOutPoint) -> Result<bool, Infallible> {
        Ok(false)
    }

    fn best_block_hash(&self) -> Result<Id<GenBlock>, Infallible> {
        Ok(self.best_block_hash)
    }

    fn estimated_size(&self) -> Option<usize> {
        None
    }
}

pub fn empty_test_utxos_view(
    best_block_hash: Id<GenBlock>,
) -> Box<dyn UtxosView<Error = Infallible>> {
    Box::new(EmptyUtxosView { best_block_hash })
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Presence {
    Absent,
    Present,
    Spent,
}

pub fn create_tx_outputs(rng: &mut (impl Rng + CryptoRng), size: u32) -> Vec<TxOutput> {
    let mut tx_outputs = vec![];
    for _ in 0..size {
        let random_amt = rng.gen_range(1..u128::MAX);
        let (_, pub_key) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
        tx_outputs.push(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(random_amt)),
            Destination::PublicKey(pub_key),
        ));
    }

    tx_outputs
}

/// randomly select half of the provided outpoints to spend, and returns it in a vec of structure of TxInput
pub fn create_tx_inputs(rng: &mut impl Rng, outpoints: &[UtxoOutPoint]) -> Vec<TxInput> {
    let to_spend = seq::index::sample(rng, outpoints.len(), outpoints.len() / 2).into_vec();
    to_spend
        .into_iter()
        .map(|idx| {
            let outpoint = outpoints.get(idx).expect("should return an outpoint");
            TxInput::from_utxo(outpoint.source_id(), outpoint.output_index())
        })
        .collect_vec()
}

/// converts the given parameters into the tuple (Outpoint, Utxo).
pub fn convert_to_utxo(
    rng: &mut impl Rng,
    output: TxOutput,
    height: u64,
    output_idx: usize,
) -> (UtxoOutPoint, Utxo) {
    let utxo_id: Id<GenBlock> = Id::new(H256::random_using(rng));
    let id = OutPointSourceId::BlockReward(utxo_id);
    let outpoint = UtxoOutPoint::new(id, output_idx as u32);
    let utxo = Utxo::new_for_blockchain(output, BlockHeight::new(height));

    (outpoint, utxo)
}

pub fn create_utxo(rng: &mut (impl Rng + CryptoRng), block_height: u64) -> (Utxo, UtxoOutPoint) {
    let random_value = rng.gen_range(0..u128::MAX);
    let is_block_reward = random_value % 3 == 0;
    inner_create_utxo(rng, is_block_reward, Some(block_height))
}

pub fn create_utxo_for_mempool(rng: &mut (impl Rng + CryptoRng)) -> (Utxo, UtxoOutPoint) {
    let random_value = rng.gen_range(0..u128::MAX);
    let is_block_reward = random_value % 3 == 0;
    inner_create_utxo(rng, is_block_reward, None)
}

pub fn create_utxo_from_reward(
    rng: &mut (impl Rng + CryptoRng),
    block_height: u64,
) -> (Utxo, UtxoOutPoint) {
    inner_create_utxo(rng, true, Some(block_height))
}

/// returns a tuple of utxo and outpoint, for testing.
fn inner_create_utxo(
    rng: &mut (impl Rng + CryptoRng),
    is_block_reward: bool,
    block_height: Option<u64>,
) -> (Utxo, UtxoOutPoint) {
    // just a random value generated, and also a random `is_block_reward` value.
    let output_value = rng.gen_range(0..u128::MAX);
    let (_, pub_key) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let output = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(output_value)),
        Destination::PublicKey(pub_key),
    );

    // generate utxo
    let utxo = match block_height {
        None => Utxo::new_for_mempool(output),
        Some(height) => Utxo::new_for_blockchain(output, BlockHeight::new(height)),
    };

    // create the id based on the `is_block_reward` value.
    let id = {
        if !is_block_reward {
            let utxo_id: Id<Transaction> = Id::new(H256::random_using(rng));
            OutPointSourceId::Transaction(utxo_id)
        } else {
            let utxo_id: Id<GenBlock> = Id::new(H256::random_using(rng));
            OutPointSourceId::BlockReward(utxo_id)
        }
    };

    let outpoint = UtxoOutPoint::new(id, 0);

    (utxo, outpoint)
}

/// inserts a random utxo in the cache.
/// returns the utxo and the outpoint.
/// # Arguments
/// `cache` - a mutable reference of the UtxosCache
/// `cache_presence` - sets the initial state of the cache.
/// `cache_flags` - sets the entry of the utxo (fresh/not, dirty/not)
/// `outpoint` - optional key to be used, rather than a randomly generated one.
pub fn insert_single_entry<P>(
    rng: &mut (impl Rng + CryptoRng),
    cache: &mut UtxosCache<P>,
    cache_presence: Presence,
    cache_flags: Option<(IsFresh, IsDirty)>,
    outpoint: Option<UtxoOutPoint>,
) -> (Utxo, UtxoOutPoint) {
    let rng_height = rng.gen_range(0..(u64::MAX - 1));
    let (utxo, outpoint_x) = create_utxo(rng, rng_height);
    let outpoint = outpoint.unwrap_or(outpoint_x);
    let key = &outpoint;

    match cache_presence {
        Presence::Absent => {
            // there shouldn't be an existing entry. Don't bother with the cache flags.
        }
        other => {
            let (is_fresh, is_dirty) = cache_flags.expect("please provide flags.");
            let entry = match other {
                Presence::Present => UtxoEntry::new(Some(utxo.clone()), is_fresh, is_dirty),
                Presence::Spent => UtxoEntry::new(None, is_fresh, is_dirty),
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
    expected_flags: Option<(IsFresh, IsDirty)>,
    is_spent: bool,
) {
    if let Some((is_fresh, is_dirty)) = expected_flags {
        let result_entry = result_entry.expect("this should have an entry inside");

        assert_eq!(IsDirty::from(result_entry.is_dirty()), is_dirty);
        assert_eq!(IsFresh::from(result_entry.is_fresh()), is_fresh);
        assert_eq!(result_entry.is_spent(), is_spent);
    } else {
        assert!(result_entry.is_none());
    }
}
