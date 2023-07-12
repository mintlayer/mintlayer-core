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

use common::address::Address;
use common::chain::stakelock::StakePoolData;
use common::chain::tokens::{OutputValue, TokenData, TokenId, TokenTransfer};
use common::chain::{
    ChainConfig, Destination, PoolId, Transaction, TransactionCreationError, TxInput, TxOutput,
};
use common::primitives::per_thousand::PerThousand;
use common::primitives::Amount;
use crypto::key::PublicKey;
use crypto::vrf::VRFPublicKey;

use crate::WalletResult;

/// The `SendRequest` struct provides the necessary information to the wallet
/// on the precise method of sending funds to a designated destination.
#[derive(Debug, Clone)]
pub struct SendRequest {
    flags: u128,

    /// The UTXOs for each input, this can be empty
    utxos: Vec<TxOutput>,

    inputs: Vec<TxInput>,

    outputs: Vec<TxOutput>,
}

pub fn make_address_output(
    chain_config: &ChainConfig,
    address: Address,
    amount: Amount,
) -> WalletResult<TxOutput> {
    let destination = address.destination(chain_config)?;

    Ok(TxOutput::Transfer(OutputValue::Coin(amount), destination))
}

pub fn make_address_output_token(
    chain_config: &ChainConfig,
    address: Address,
    amount: Amount,
    token_id: TokenId,
) -> WalletResult<TxOutput> {
    let destination = address.destination(chain_config)?;

    Ok(TxOutput::Transfer(
        OutputValue::Token(Box::new(TokenData::TokenTransfer(TokenTransfer {
            token_id,
            amount,
        }))),
        destination,
    ))
}

pub fn make_stake_output(
    pool_id: PoolId,
    amount: Amount,
    staker: PublicKey,
    decommission_key: PublicKey,
    vrf_public_key: VRFPublicKey,
    margin_ratio_per_thousand: PerThousand,
    cost_per_block: Amount,
) -> WalletResult<TxOutput> {
    let staker = Destination::PublicKey(staker);
    let decommission_key = Destination::PublicKey(decommission_key);

    let stake_data = StakePoolData::new(
        amount,
        staker,
        vrf_public_key,
        decommission_key,
        margin_ratio_per_thousand,
        cost_per_block,
    );
    Ok(TxOutput::CreateStakePool(pool_id, stake_data.into()))
}

impl SendRequest {
    pub fn new() -> Self {
        Self {
            flags: 0,
            utxos: Vec::new(),
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }

    pub fn from_transaction(transaction: Transaction, utxos: Vec<TxOutput>) -> Self {
        Self {
            flags: transaction.flags(),
            utxos,
            inputs: transaction.inputs().to_vec(),
            outputs: transaction.outputs().to_vec(),
        }
    }

    pub fn inputs(&self) -> &[TxInput] {
        &self.inputs
    }

    pub fn outputs(&self) -> &[TxOutput] {
        &self.outputs
    }

    pub fn utxos(&self) -> &[TxOutput] {
        &self.utxos
    }

    pub fn with_inputs(mut self, utxos: impl IntoIterator<Item = (TxInput, TxOutput)>) -> Self {
        for (outpoint, txo) in utxos {
            self.inputs.push(outpoint);
            self.utxos.push(txo);
        }
        self
    }

    pub fn with_outputs(mut self, outputs: impl IntoIterator<Item = TxOutput>) -> Self {
        self.outputs.extend(outputs);
        self
    }

    pub fn get_outputs_mut(&mut self) -> &mut Vec<TxOutput> {
        &mut self.outputs
    }

    pub fn into_transaction_and_utxos(
        self,
    ) -> Result<(Transaction, Vec<TxOutput>), TransactionCreationError> {
        let tx = Transaction::new(self.flags, self.inputs, self.outputs)?;
        Ok((tx, self.utxos))
    }
}
