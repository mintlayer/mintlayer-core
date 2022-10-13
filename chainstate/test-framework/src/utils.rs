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

use crate::TestChainstate;
use chainstate::chainstate_interface::ChainstateInterface;
use common::chain::signature::inputsig::InputWitness;
use common::chain::tokens::TokenData;
use common::chain::tokens::TokenTransferV1;
use common::chain::OutPointSourceId;
use common::chain::TxInput;
use common::chain::TxOutput;
use common::{
    chain::{tokens::OutputValue, Destination, OutputPurpose},
    primitives::Amount,
};
use crypto::random::Rng;

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

fn create_utxo_data(
    chainstate: &TestChainstate,
    outsrc: OutPointSourceId,
    index: usize,
    output: &TxOutput,
    rng: &mut impl Rng,
) -> Option<(InputWitness, TxInput, TxOutput)> {
    Some((
        empty_witness(rng),
        TxInput::new(outsrc.clone(), index as u32),
        match output.value() {
            OutputValue::Coin(output_value) => {
                let spent_value = Amount::from_atoms(rng.gen_range(0..output_value.into_atoms()));
                let new_value = (*output_value - spent_value).unwrap();
                utils::ensure!(new_value >= Amount::from_atoms(1));
                TxOutput::new(
                    OutputValue::Coin(new_value),
                    OutputPurpose::Transfer(anyonecanspend_address()),
                )
                // FIXME: issue a token from coin
            }
            OutputValue::Token(token_data) => match &**token_data {
                // FIXME: Burn output never created
                TokenData::TokenTransferV1(_transfer) => TxOutput::new(
                    OutputValue::Token(token_data.clone()),
                    OutputPurpose::Transfer(anyonecanspend_address()),
                ),
                TokenData::TokenIssuanceV1(issuance) => {
                    new_token_transfer_output(chainstate, outsrc, issuance.amount_to_issue)
                }
                TokenData::NftIssuanceV1(_issuance) => {
                    new_token_transfer_output(chainstate, outsrc, Amount::from_atoms(1))
                }
                TokenData::TokenBurnV1(_burn) => return None,
            },
        },
    ))
}

fn new_token_transfer_output(
    chainstate: &TestChainstate,
    outsrc: OutPointSourceId,
    amount: Amount,
) -> TxOutput {
    TxOutput::new(
        OutputValue::Token(Box::new(TokenData::TokenTransferV1(TokenTransferV1 {
            token_id: match outsrc {
                OutPointSourceId::Transaction(prev_tx) => {
                    chainstate.get_token_id_from_issuance_tx(&prev_tx).expect("ok").expect("some")
                }
                OutPointSourceId::BlockReward(_) => {
                    panic!("cannot issue token in block reward")
                }
            },
            amount,
        }))),
        OutputPurpose::Transfer(anyonecanspend_address()),
    )
}
