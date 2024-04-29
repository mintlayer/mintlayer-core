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
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            sighash::signature_hash,
            Transactable,
        },
        timelock::OutputTimeLock,
        ChainConfig, Destination, TxOutput,
    },
    primitives::H256,
};
use pos_accounting::PoSAccountingView;
use utxo::UtxosView;

use crate::{
    helpers::{BlockchainState, SourceBlockState},
    timelock_check::check_timelock,
};

use self::error::Error;

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

    pub fn from_output_for_tx<
        'a,
        T: Transactable,
        U: UtxosView,
        P: PoSAccountingView<Error = pos_accounting::Error>,
    >(
        _chain_config: &ChainConfig,
        input_utxo: TxOutput,
        tx: &T,
        inputs_utxos: &[Option<&TxOutput>],
        input_num: usize,
        _utxos_view: &'a U,
        accounting_view: &'a P,
    ) -> Option<MintScript> {
        match input_utxo {
            TxOutput::Transfer(_val, dest) => {
                script_from_transactable(dest, tx, inputs_utxos, input_num)
            }
            TxOutput::LockThenTransfer(_val, dest, tl) => {
                let sig_check = script_from_transactable(dest, tx, inputs_utxos, input_num)?;

                Some(MintScript::Threshold(
                    2,
                    vec![sig_check, MintScript::CheckTimelock(tl)],
                ))
            }
            TxOutput::CreateStakePool(_id, pos_data) => script_from_transactable(
                pos_data.decommission_key().clone(),
                tx,
                inputs_utxos,
                input_num,
            ),
            TxOutput::ProduceBlockFromStake(_, pool_id) => {
                let pos_data = accounting_view
                    .get_pool_data(pool_id)
                    .ok()?
                    .ok_or(Error::PoolDataNotFound(pool_id))
                    .ok()?;

                script_from_transactable(
                    pos_data.decommission_destination().clone(),
                    tx,
                    inputs_utxos,
                    input_num,
                )
            }
            TxOutput::CreateDelegationId(_, _) => None,
            TxOutput::DelegateStaking(_, delegation_id) => {
                let dest = accounting_view
                    .get_delegation_data(delegation_id)
                    .ok()?
                    .ok_or(Error::DelegationDataNotFound(delegation_id))
                    .ok()?
                    .spend_destination()
                    .clone();

                script_from_transactable(dest, tx, inputs_utxos, input_num)
            }
            TxOutput::IssueFungibleToken(_) => None,
            TxOutput::IssueNft(_, _, d) => script_from_transactable(d, tx, inputs_utxos, input_num),
            TxOutput::DataDeposit(_) => None,
            TxOutput::Burn(_) => None,
        }
    }

    pub fn from_output_for_block_reward<
        'a,
        T: Transactable,
        U: UtxosView,
        P: PoSAccountingView<Error = pos_accounting::Error>,
    >(
        _chain_config: &ChainConfig,
        input_utxo: TxOutput,
        tx: &T,
        inputs_utxos: &[Option<&TxOutput>],
        input_num: usize,
        _utxos_view: &'a U,
        _accounting_view: &'a P,
    ) -> Option<MintScript> {
        match input_utxo {
            TxOutput::Transfer(_, _) => None,
            TxOutput::LockThenTransfer(_, _, _) => None,
            TxOutput::CreateStakePool(_id, pos_data) => {
                script_from_transactable(pos_data.staker().clone(), tx, inputs_utxos, input_num)
            }
            TxOutput::ProduceBlockFromStake(d, _) => {
                script_from_transactable(d.clone(), tx, inputs_utxos, input_num)
            }
            TxOutput::CreateDelegationId(_, _) => None,
            TxOutput::DelegateStaking(_, _) => None,
            TxOutput::IssueFungibleToken(_) => None,
            TxOutput::IssueNft(_, _, _) => None,
            TxOutput::DataDeposit(_) => None,
            TxOutput::Burn(_) => None,
        }
    }
}

pub fn script_from_transactable<T: Transactable>(
    outpoint_destination: Destination,
    tx: &T,
    inputs_utxos: &[Option<&TxOutput>],
    input_num: usize,
) -> Option<MintScript> {
    let sigs = tx.signatures()?;
    let input_witness = sigs.get(input_num)?;

    match input_witness {
        InputWitness::NoSignature(_) => match outpoint_destination {
            Destination::PublicKeyHash(_)
            | Destination::PublicKey(_)
            | Destination::ScriptHash(_)
            | Destination::ClassicMultisig(_) => None,
            Destination::AnyoneCanSpend => Some(MintScript::Bool(true)),
        },
        InputWitness::Standard(witness) => {
            let sighash =
                signature_hash(witness.sighash_type(), tx, inputs_utxos, input_num).ok()?;
            Some(MintScript::CheckSig(
                sighash,
                witness.clone(),
                outpoint_destination.clone(),
            ))
        }
    }
}
