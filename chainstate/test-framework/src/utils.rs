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

use crate::{framework::BlockOutputs, TestChainstate};
use chainstate::chainstate_interface::ChainstateInterface;
use common::{
    chain::{
        signature::inputsig::InputWitness,
        tokens::{OutputValue, TokenData, TokenTransfer},
        Block, Destination, Genesis, OutPointSourceId, OutputPurpose, TxInput, TxOutput,
    },
    primitives::{Amount, Idable},
};
use crypto::random::{CryptoRng, Rng};
use test_utils::nft_utils::*;

pub fn empty_witness(rng: &mut impl Rng) -> InputWitness {
    use crypto::random::SliceRandom;
    let mut msg: Vec<u8> = (1..100).collect();
    msg.shuffle(rng);
    InputWitness::NoSignature(Some(msg))
}

pub fn anyonecanspend_address() -> Destination {
    Destination::AnyoneCanSpend
}

pub fn create_new_outputs(
    chainstate: &TestChainstate,
    srcid: OutPointSourceId,
    outs: &[TxOutput],
    rng: &mut impl Rng,
) -> Vec<(InputWitness, TxInput, TxOutput)> {
    outs.iter()
        .enumerate()
        .filter_map(move |(index, output)| {
            create_utxo_data(chainstate, srcid.clone(), index, output, rng)
        })
        .collect()
}

pub fn create_utxo_data(
    chainstate: &TestChainstate,
    outsrc: OutPointSourceId,
    index: usize,
    output: &TxOutput,
    rng: &mut impl Rng,
) -> Option<(InputWitness, TxInput, TxOutput)> {
    let new_output = match output.value() {
        OutputValue::Coin(output_value) => {
            let spent_value = Amount::from_atoms(rng.gen_range(0..output_value.into_atoms()));
            let new_value = (*output_value - spent_value).unwrap();
            utils::ensure!(new_value >= Amount::from_atoms(1));
            TxOutput::new(
                OutputValue::Coin(new_value),
                OutputPurpose::Transfer(anyonecanspend_address()),
            )
        }
        OutputValue::Token(token_data) => match &**token_data {
            TokenData::TokenTransfer(_transfer) => TxOutput::new(
                OutputValue::Token(token_data.clone()),
                OutputPurpose::Transfer(anyonecanspend_address()),
            ),
            TokenData::TokenIssuance(issuance) => {
                new_token_transfer_output(chainstate, &outsrc, issuance.amount_to_issue)
            }
            TokenData::NftIssuance(_issuance) => {
                new_token_transfer_output(chainstate, &outsrc, Amount::from_atoms(1))
            }
        },
    };

    Some((
        empty_witness(rng),
        TxInput::new(outsrc, index as u32),
        new_output,
    ))
}

/// Given an output as in input creates multiple new random outputs.
pub fn create_multiple_utxo_data(
    chainstate: &TestChainstate,
    outsrc: OutPointSourceId,
    index: usize,
    output: &TxOutput,
    rng: &mut (impl Rng + CryptoRng),
) -> Option<(InputWitness, TxInput, Vec<TxOutput>)> {
    let num_outputs = rng.gen_range(1..10);
    let new_outputs = match output.value() {
        OutputValue::Coin(output_value) => {
            let switch = rng.gen_range(0..3);
            if switch == 0 {
                // issue nft
                let min_tx_fee = chainstate.get_chain_config().token_min_issuance_fee();
                if *output_value >= min_tx_fee {
                    // Coin output is created intentionally besides issuance output in order to not waste utxo
                    // (e.g. single genesis output on issuance)
                    vec![
                        TxOutput::new(
                            random_nft_issuance(chainstate.get_chain_config(), rng).into(),
                            OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                        ),
                        TxOutput::new(OutputValue::Coin(min_tx_fee), OutputPurpose::Burn),
                    ]
                } else {
                    return None;
                }
            } else if switch == 1 {
                // issue token
                let min_tx_fee = chainstate.get_chain_config().token_min_issuance_fee();
                if *output_value >= min_tx_fee {
                    // Coin output is created intentionally besides issuance output in order to not waste utxo
                    // (e.g. single genesis output on issuance)
                    vec![
                        TxOutput::new(
                            random_token_issuance(chainstate.get_chain_config(), rng).into(),
                            OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                        ),
                        TxOutput::new(OutputValue::Coin(min_tx_fee), OutputPurpose::Burn),
                    ]
                } else {
                    return None;
                }
            } else {
                // spend the coin with multiple outputs
                (0..num_outputs)
                    .into_iter()
                    .map(|_| {
                        let new_value = Amount::from_atoms(output_value.into_atoms() / num_outputs);
                        debug_assert!(new_value >= Amount::from_atoms(1));
                        TxOutput::new(
                            OutputValue::Coin(new_value),
                            OutputPurpose::Transfer(anyonecanspend_address()),
                        )
                    })
                    .collect()
            }
        }
        OutputValue::Token(token_data) => match &**token_data {
            TokenData::TokenTransfer(transfer) => {
                if rng.gen::<bool>() {
                    // burn transferred tokens
                    let amount_to_burn = if transfer.amount.into_atoms() > 1 {
                        Amount::from_atoms(rng.gen_range(1..transfer.amount.into_atoms()))
                    } else {
                        transfer.amount
                    };
                    vec![TxOutput::new(
                        TokenTransfer {
                            token_id: transfer.token_id,
                            amount: amount_to_burn,
                        }
                        .into(),
                        OutputPurpose::Burn,
                    )]
                } else {
                    // transfer tokens again
                    if transfer.amount.into_atoms() >= num_outputs {
                        // transfer with multiple outputs
                        (0..num_outputs)
                            .into_iter()
                            .map(|_| {
                                let amount =
                                    Amount::from_atoms(transfer.amount.into_atoms() / num_outputs);
                                TxOutput::new(
                                    TokenTransfer {
                                        token_id: transfer.token_id,
                                        amount,
                                    }
                                    .into(),
                                    OutputPurpose::Transfer(anyonecanspend_address()),
                                )
                            })
                            .collect()
                    } else {
                        // transfer with a single output
                        vec![TxOutput::new(
                            OutputValue::Token(token_data.clone()),
                            OutputPurpose::Transfer(anyonecanspend_address()),
                        )]
                    }
                }
            }
            TokenData::TokenIssuance(issuance) => {
                if rng.gen::<bool>() {
                    vec![new_token_burn_output(
                        chainstate,
                        &outsrc,
                        Amount::from_atoms(rng.gen_range(1..issuance.amount_to_issue.into_atoms())),
                    )]
                } else {
                    vec![new_token_transfer_output(chainstate, &outsrc, issuance.amount_to_issue)]
                }
            }
            TokenData::NftIssuance(_issuance) => {
                if rng.gen::<bool>() {
                    vec![new_token_burn_output(chainstate, &outsrc, Amount::from_atoms(1))]
                } else {
                    vec![new_token_transfer_output(chainstate, &outsrc, Amount::from_atoms(1))]
                }
            }
        },
    };

    Some((
        empty_witness(rng),
        TxInput::new(outsrc, index as u32),
        new_outputs,
    ))
}

fn new_token_transfer_output(
    chainstate: &TestChainstate,
    outsrc: &OutPointSourceId,
    amount: Amount,
) -> TxOutput {
    TxOutput::new(
        TokenTransfer {
            token_id: match outsrc {
                OutPointSourceId::Transaction(prev_tx) => {
                    chainstate.get_token_id_from_issuance_tx(prev_tx).expect("ok").expect("some")
                }
                OutPointSourceId::BlockReward(_) => {
                    panic!("cannot issue token in block reward")
                }
            },
            amount,
        }
        .into(),
        OutputPurpose::Transfer(anyonecanspend_address()),
    )
}

fn new_token_burn_output(
    chainstate: &TestChainstate,
    outsrc: &OutPointSourceId,
    amount_to_burn: Amount,
) -> TxOutput {
    TxOutput::new(
        TokenTransfer {
            token_id: match outsrc {
                OutPointSourceId::Transaction(prev_tx) => {
                    chainstate.get_token_id_from_issuance_tx(prev_tx).expect("ok").expect("some")
                }
                OutPointSourceId::BlockReward(_) => {
                    panic!("cannot issue token in block reward")
                }
            },
            amount: amount_to_burn,
        }
        .into(),
        OutputPurpose::Burn,
    )
}

pub fn outputs_from_genesis(genesis: &Genesis) -> BlockOutputs {
    [(
        OutPointSourceId::BlockReward(genesis.get_id().into()),
        genesis.utxos().to_vec(),
    )]
    .into_iter()
    .collect()
}

pub fn outputs_from_block(blk: &Block) -> BlockOutputs {
    std::iter::once((
        OutPointSourceId::BlockReward(blk.get_id().into()),
        blk.block_reward().outputs().to_vec(),
    ))
    .chain(blk.transactions().iter().map(|tx| {
        (
            OutPointSourceId::Transaction(tx.transaction().get_id()),
            tx.transaction().outputs().clone(),
        )
    }))
    .collect()
}
