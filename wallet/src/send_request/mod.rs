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
use common::chain::output_value::OutputValue;
use common::chain::stakelock::StakePoolData;
use common::chain::timelock::OutputTimeLock::ForBlockCount;
use common::chain::tokens::{Metadata, TokenId, TokenIssuance};
use common::chain::{
    ChainConfig, Destination, PoolId, Transaction, TransactionCreationError, TxInput, TxOutput,
};
use common::primitives::per_thousand::PerThousand;
use common::primitives::{Amount, BlockHeight};
use crypto::key::PublicKey;
use crypto::vrf::VRFPublicKey;
use utils::ensure;

use crate::{WalletError, WalletResult};

/// The `SendRequest` struct provides the necessary information to the wallet
/// on the precise method of sending funds to a designated destination.
#[derive(Debug, Clone)]
pub struct SendRequest {
    flags: u128,

    /// The UTXOs for each input, this can be empty
    utxos: Vec<Option<TxOutput>>,

    /// destination for each input
    destinations: Vec<Destination>,

    inputs: Vec<TxInput>,

    outputs: Vec<TxOutput>,
}

pub fn make_address_output(
    chain_config: &ChainConfig,
    address: Address<Destination>,
    amount: Amount,
) -> WalletResult<TxOutput> {
    let destination = address.decode_object(chain_config)?;

    Ok(TxOutput::Transfer(OutputValue::Coin(amount), destination))
}

pub fn make_address_output_token(
    chain_config: &ChainConfig,
    address: Address<Destination>,
    amount: Amount,
    token_id: TokenId,
) -> WalletResult<TxOutput> {
    let destination = address.decode_object(chain_config)?;

    Ok(TxOutput::Transfer(
        OutputValue::TokenV1(token_id, amount),
        destination,
    ))
}

pub fn make_issue_token_outputs(
    token_issuance: TokenIssuance,
    chain_config: &ChainConfig,
    block_height: BlockHeight,
) -> WalletResult<Vec<TxOutput>> {
    chainstate::check_tokens_issuance(chain_config, block_height, &token_issuance)?;

    let issuance_output = TxOutput::IssueFungibleToken(Box::new(token_issuance));

    Ok(vec![issuance_output])
}

pub fn make_mint_token_outputs(
    token_id: TokenId,
    amount: Amount,
    address: Address<Destination>,
    chain_config: &ChainConfig,
) -> WalletResult<Vec<TxOutput>> {
    let destination = address.decode_object(chain_config)?;
    let mint_output = TxOutput::Transfer(OutputValue::TokenV1(token_id, amount), destination);

    Ok(vec![mint_output])
}

pub fn make_unmint_token_outputs(token_id: TokenId, amount: Amount) -> Vec<TxOutput> {
    let burn_tokens = TxOutput::Burn(OutputValue::TokenV1(token_id, amount));
    vec![burn_tokens]
}

pub fn make_create_delegation_output(
    chain_config: &ChainConfig,
    address: Address<Destination>,
    pool_id: PoolId,
) -> WalletResult<TxOutput> {
    let destination = address.decode_object(chain_config)?;

    Ok(TxOutput::CreateDelegationId(destination, pool_id))
}

pub fn make_address_output_from_delegation(
    chain_config: &ChainConfig,
    address: Address<Destination>,
    amount: Amount,
    current_block_height: BlockHeight,
) -> WalletResult<TxOutput> {
    let destination = address.decode_object(chain_config)?;
    let num_blocks_to_lock: i64 =
        chain_config.spend_share_maturity_distance(current_block_height).into();

    Ok(TxOutput::LockThenTransfer(
        OutputValue::Coin(amount),
        destination,
        ForBlockCount(num_blocks_to_lock as u64),
    ))
}

pub fn make_decomission_stake_pool_output(
    chain_config: &ChainConfig,
    destination: Destination,
    amount: Amount,
    current_block_height: BlockHeight,
) -> WalletResult<TxOutput> {
    let num_blocks_to_lock: i64 =
        chain_config.decommission_pool_maturity_distance(current_block_height).into();

    Ok(TxOutput::LockThenTransfer(
        OutputValue::Coin(amount),
        destination,
        ForBlockCount(num_blocks_to_lock as u64),
    ))
}

/// Helper struct to reduce the number of arguments passed around
pub struct StakePoolDataArguments {
    pub amount: Amount,
    pub margin_ratio_per_thousand: PerThousand,
    pub cost_per_block: Amount,
}

pub fn make_stake_output(
    pool_id: PoolId,
    arguments: StakePoolDataArguments,
    staker: PublicKey,
    decommission_key: PublicKey,
    vrf_public_key: VRFPublicKey,
) -> WalletResult<TxOutput> {
    let staker = Destination::PublicKey(staker);
    let decommission_key = Destination::PublicKey(decommission_key);

    let stake_data = StakePoolData::new(
        arguments.amount,
        staker,
        vrf_public_key,
        decommission_key,
        arguments.margin_ratio_per_thousand,
        arguments.cost_per_block,
    );
    Ok(TxOutput::CreateStakePool(pool_id, stake_data.into()))
}

pub fn make_data_deposit_output(
    chain_config: &ChainConfig,
    data: Vec<u8>,
) -> WalletResult<Vec<TxOutput>> {
    ensure!(
        data.len() <= chain_config.data_deposit_max_size(),
        WalletError::DataDepositToBig(data.len(), chain_config.data_deposit_max_size())
    );
    ensure!(!data.is_empty(), WalletError::EmptyDataDeposit);

    Ok(vec![TxOutput::DataDeposit(data)])
}

pub struct IssueNftArguments {
    pub metadata: Metadata,
    pub destination: Destination,
}

type TxAndInputs = (Transaction, Vec<Option<TxOutput>>, Vec<Destination>);

impl SendRequest {
    pub fn new() -> Self {
        Self {
            flags: 0,
            utxos: Vec::new(),
            destinations: Vec::new(),
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }

    pub fn from_transaction(transaction: Transaction, utxos: Vec<TxOutput>) -> WalletResult<Self> {
        let destinations = utxos
            .iter()
            .map(|utxo| {
                get_tx_output_destination(utxo).cloned().ok_or_else(|| {
                    WalletError::UnsupportedTransactionOutput(Box::new(utxo.clone()))
                })
            })
            .collect::<WalletResult<Vec<_>>>()?;

        Ok(Self {
            flags: transaction.flags(),
            utxos: utxos.into_iter().map(Some).collect(),
            destinations,
            inputs: transaction.inputs().to_vec(),
            outputs: transaction.outputs().to_vec(),
        })
    }

    pub fn inputs(&self) -> &[TxInput] {
        &self.inputs
    }

    pub fn destinations(&self) -> &[Destination] {
        &self.destinations
    }

    pub fn outputs(&self) -> &[TxOutput] {
        &self.outputs
    }

    pub fn with_inputs_and_destinations(
        mut self,
        utxos: impl IntoIterator<Item = (TxInput, Destination)>,
    ) -> Self {
        for (outpoint, destination) in utxos {
            self.inputs.push(outpoint);
            self.destinations.push(destination);
            self.utxos.push(None);
        }

        self
    }

    pub fn with_inputs(
        mut self,
        utxos: impl IntoIterator<Item = (TxInput, TxOutput)>,
    ) -> WalletResult<Self> {
        for (outpoint, txo) in utxos {
            self.inputs.push(outpoint);
            self.destinations.push(
                get_tx_output_destination(&txo).cloned().ok_or_else(|| {
                    WalletError::UnsupportedTransactionOutput(Box::new(txo.clone()))
                })?,
            );
            self.utxos.push(Some(txo));
        }

        Ok(self)
    }

    pub fn with_outputs(mut self, outputs: impl IntoIterator<Item = TxOutput>) -> Self {
        self.outputs.extend(outputs);
        self
    }

    pub fn get_outputs_mut(&mut self) -> &mut Vec<TxOutput> {
        &mut self.outputs
    }

    pub fn into_transaction_and_utxos(self) -> Result<TxAndInputs, TransactionCreationError> {
        let tx = Transaction::new(self.flags, self.inputs, self.outputs)?;
        Ok((tx, self.utxos, self.destinations))
    }
}

pub fn get_tx_output_destination(txo: &TxOutput) -> Option<&Destination> {
    match txo {
        TxOutput::Transfer(_, d)
        | TxOutput::LockThenTransfer(_, d, _)
        | TxOutput::CreateDelegationId(d, _)
        | TxOutput::IssueNft(_, _, d)
        | TxOutput::ProduceBlockFromStake(d, _) => Some(d),
        TxOutput::CreateStakePool(_, data) => Some(data.staker()),
        TxOutput::IssueFungibleToken(_)
        | TxOutput::Burn(_)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::DataDeposit(_) => None,
    }
}
