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
        output_value::OutputValue,
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::{TokenId, TokenIssuanceV1, TokenIssuanceVersioned, TokenTotalSupply},
        Block, DelegationId, Destination, GenBlock, OutPointSourceId, PoolId, TokenOutput, TxInput,
        TxOutput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, Compact, Id, H256},
};
use crypto::{
    random::{seq::IteratorRandom, Rng},
    vrf::{transcript::TranscriptAssembler, VRFKeyKind, VRFPrivateKey},
};
use itertools::Itertools;
use utxo::{Utxo, UtxosDBInMemoryImpl};

use super::*;

mod constraints_tests;
mod purpose_tests;

fn transfer() -> TxOutput {
    TxOutput::Transfer(OutputValue::Coin(Amount::ZERO), Destination::AnyoneCanSpend)
}

fn burn() -> TxOutput {
    TxOutput::Burn(OutputValue::Coin(Amount::ZERO))
}

fn lock_then_transfer() -> TxOutput {
    TxOutput::LockThenTransfer(
        OutputValue::Coin(Amount::ZERO),
        Destination::AnyoneCanSpend,
        OutputTimeLock::ForBlockCount(1),
    )
}

fn stake_pool() -> TxOutput {
    let (_, vrf_pub_key) = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel);
    TxOutput::CreateStakePool(
        PoolId::new(H256::zero()),
        Box::new(StakePoolData::new(
            Amount::ZERO,
            Destination::AnyoneCanSpend,
            vrf_pub_key,
            Destination::AnyoneCanSpend,
            PerThousand::new(0).unwrap(),
            Amount::ZERO,
        )),
    )
}

fn produce_block() -> TxOutput {
    TxOutput::ProduceBlockFromStake(Destination::AnyoneCanSpend, PoolId::new(H256::zero()))
}

fn create_delegation() -> TxOutput {
    TxOutput::CreateDelegationId(Destination::AnyoneCanSpend, PoolId::new(H256::zero()))
}

fn delegate_staking() -> TxOutput {
    TxOutput::DelegateStaking(Amount::ZERO, DelegationId::new(H256::zero()))
}

fn issue_tokens() -> TxOutput {
    TxOutput::Tokens(TokenOutput::IssueFungibleToken(Box::new(
        TokenIssuanceVersioned::V1(TokenIssuanceV1 {
            token_ticker: Vec::new(),
            number_of_decimals: 0,
            metadata_uri: Vec::new(),
            supply_limit: TokenTotalSupply::Unlimited,
            reissuance_controller: Destination::AnyoneCanSpend,
        }),
    )))
}

fn mint_tokens() -> TxOutput {
    TxOutput::Tokens(TokenOutput::MintTokens(
        TokenId::new(H256::zero()),
        Amount::ZERO,
        Destination::AnyoneCanSpend,
    ))
}

fn redeem_tokens() -> TxOutput {
    TxOutput::Tokens(TokenOutput::RedeemTokens(
        TokenId::new(H256::zero()),
        Amount::ZERO,
    ))
}

fn lock_tokens_supply() -> TxOutput {
    TxOutput::Tokens(TokenOutput::LockCirculatingSupply(TokenId::new(
        H256::zero(),
    )))
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

fn make_block(kernels: Vec<TxInput>, reward_outputs: Vec<TxOutput>) -> Block {
    let (sk, _) = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel);
    let vrf_data = sk.produce_vrf_data(TranscriptAssembler::new(b"abc").finalize().into());
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
