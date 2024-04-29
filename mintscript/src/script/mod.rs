// Copyright (c) 2024 RBB S.r.l
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

pub mod error;

use common::{
    chain::{
        signature::{
            inputsig::standard_signature::StandardInputSignature, sighash::signature_hash,
            Transactable,
        },
        timelock::OutputTimeLock,
        ChainConfig, Destination, TxOutput,
    },
    primitives::H256,
};

use crate::{
    helpers::{BlockchainState, SourceBlockState},
    timelock_check::check_timelock,
};

#[derive(Debug)]
pub enum MintScript {
    Bool(bool),
    Threshold(usize, Vec<MintScript>),
    CheckSig(H256, StandardInputSignature, Destination),
    CheckTimelock(OutputTimeLock),
}

impl MintScript {
    pub fn try_into_bool(
        &self,
        chain_config: &ChainConfig,
        source_block_info: &SourceBlockState,
        blockchain_state: &BlockchainState,
    ) -> Option<bool> {
        match self {
            MintScript::Bool(b) => Some(*b),
            MintScript::Threshold(count, v) => Some(
                v.iter()
                    .map(|el| {
                        el.try_into_bool(chain_config, source_block_info, blockchain_state)
                            .unwrap_or(false)
                    })
                    .filter(|v| *v)
                    .count()
                    >= *count,
            ),
            MintScript::CheckSig(sighash, sig, d) => {
                Some(sig.verify_signature(chain_config, d, sighash).ok().is_some())
            }
            MintScript::CheckTimelock(tl) => Some(
                check_timelock(
                    &source_block_info.block_height,
                    &source_block_info.block_timestamp,
                    tl,
                    &blockchain_state.current_block_height,
                    &blockchain_state.tip_block_timestamp,
                )
                .ok()
                .is_some(),
            ),
        }
    }

    pub fn from_output_for_tx<T: Transactable>(
        _chain_config: &ChainConfig,
        input_utxo: TxOutput,
        tx: &T,
        inputs_utxos: &[Option<&TxOutput>],
        input_num: usize,
    ) -> Option<MintScript> {
        match input_utxo {
            TxOutput::Transfer(_val, dest) => {
                let witness = tx.signatures()?.get(input_num)?.as_standard_signature()?;
                let sighash =
                    signature_hash(witness.sighash_type(), tx, inputs_utxos, input_num).ok()?;

                Some(MintScript::CheckSig(sighash, witness.clone(), dest))
            }
            TxOutput::LockThenTransfer(_val, dest, tl) => {
                let witness = tx.signatures()?.get(input_num)?.as_standard_signature()?;
                let sighash =
                    signature_hash(witness.sighash_type(), tx, inputs_utxos, input_num).ok()?;

                Some(MintScript::Threshold(
                    2,
                    vec![
                        MintScript::CheckSig(sighash, witness.clone(), dest),
                        MintScript::CheckTimelock(tl),
                    ],
                ))
            }
            TxOutput::CreateStakePool(_id, pos_data) => {
                let witness = tx.signatures()?.get(input_num)?.as_standard_signature()?;
                let sighash =
                    signature_hash(witness.sighash_type(), tx, inputs_utxos, input_num).ok()?;

                Some(MintScript::CheckSig(
                    sighash,
                    witness.clone(),
                    pos_data.decommission_key().clone(),
                ))
            }
            // TODO(PR): Complete this
            TxOutput::ProduceBlockFromStake(_, _) => None,
            TxOutput::CreateDelegationId(_, _) => None,
            TxOutput::DelegateStaking(_, _) => None,
            TxOutput::IssueFungibleToken(_) => None,
            TxOutput::IssueNft(_, _, _) => None,
            TxOutput::DataDeposit(_) => None,
            TxOutput::Burn(_) => None,
        }
    }
}
