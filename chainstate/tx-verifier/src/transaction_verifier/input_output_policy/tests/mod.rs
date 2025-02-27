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

use std::collections::BTreeMap;

use common::{
    chain::{
        block::{consensus_data::PoSData, timestamp::BlockTimestamp, BlockReward, ConsensusData},
        Block, DelegationId, GenBlock, OutPointSourceId, PoolId, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Compact, Id, H256},
};
use crypto::vrf::{transcript::no_rng::VRFTranscript, VRFKeyKind, VRFPrivateKey, VRFPublicKey};
use itertools::Itertools;
use randomness::{seq::IteratorRandom, Rng};
use test_utils::random::{make_seedable_rng, Seed};
use utxo::{Utxo, UtxosDBInMemoryImpl};

use super::*;

mod constraints_tests;
mod outputs_utils;
mod purpose_tests;
mod reward_tests;

fn get_random_inputs_combination(
    rng: &mut impl Rng,
    source: &[TxInput],
    result_len: usize,
) -> Vec<TxInput> {
    source
        .iter()
        .combinations_with_replacement(result_len)
        .choose(rng)
        .unwrap()
        .into_iter()
        .cloned()
        .collect::<Vec<_>>()
}

fn get_random_outputs_combination(
    rng: &mut impl Rng,
    source: &[TxOutput],
    result_len: usize,
) -> Vec<TxOutput> {
    source
        .iter()
        .combinations_with_replacement(result_len)
        .choose(rng)
        .unwrap()
        .into_iter()
        .cloned()
        .collect::<Vec<_>>()
}

lazy_static::lazy_static! {
    static ref VRF_KEYS: (VRFPrivateKey, VRFPublicKey) = {
        let mut rng = make_seedable_rng(Seed(0));
        VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel)
    };
}

fn make_block(kernels: Vec<TxInput>, reward_outputs: Vec<TxOutput>) -> Block {
    let vrf_data = VRF_KEYS.0.produce_vrf_data(VRFTranscript::new(b"abc"));
    Block::new(
        vec![],
        Id::<GenBlock>::new(H256::zero()),
        BlockTimestamp::from_int_seconds(0),
        ConsensusData::PoS(Box::new(PoSData::new(
            kernels,
            vec![],
            PoolId::new(H256::zero()),
            vrf_data,
            Compact(1),
        ))),
        BlockReward::new(reward_outputs),
    )
    .unwrap()
}

fn make_block_no_kernel(reward_outputs: Vec<TxOutput>) -> Block {
    Block::new(
        vec![],
        Id::<GenBlock>::new(H256::zero()),
        BlockTimestamp::from_int_seconds(0),
        ConsensusData::None,
        BlockReward::new(reward_outputs),
    )
    .unwrap()
}

pub fn prepare_utxos_and_tx(
    rng: &mut impl Rng,
    input_utxos: Vec<TxOutput>,
    outputs: Vec<TxOutput>,
) -> (UtxosDBInMemoryImpl, Transaction) {
    let utxos = input_utxos
        .into_iter()
        .enumerate()
        .map(|(i, output)| {
            (
                UtxoOutPoint::new(
                    OutPointSourceId::Transaction(Id::new(H256::random_using(rng))),
                    i as u32,
                ),
                Utxo::new_for_mempool(output),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let inputs: Vec<TxInput> = utxos.keys().map(|outpoint| outpoint.clone().into()).collect();

    (
        UtxosDBInMemoryImpl::new(Id::<GenBlock>::new(H256::zero()), utxos),
        Transaction::new(0, inputs, outputs).unwrap(),
    )
}

fn prepare_utxos_and_tx_with_random_combinations(
    rng: &mut impl Rng,
    origin_input_utxos: &[TxOutput],
    number_of_inputs: usize,
    origin_outputs: &[TxOutput],
    number_of_outputs: usize,
    extra_output: Option<TxOutput>,
) -> (UtxosDBInMemoryImpl, Transaction) {
    let input_utxos = get_random_outputs_combination(rng, origin_input_utxos, number_of_inputs);

    let outputs = match extra_output {
        Some(extra) => get_random_outputs_combination(rng, origin_outputs, number_of_outputs)
            .into_iter()
            .chain(std::iter::once(extra))
            .collect(),
        None => get_random_outputs_combination(rng, origin_outputs, number_of_outputs),
    };

    prepare_utxos_and_tx(rng, input_utxos, outputs)
}
