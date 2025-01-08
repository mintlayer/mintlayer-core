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
use std::mem::take;

use common::address::Address;
use common::chain::output_value::OutputValue;
use common::chain::stakelock::StakePoolData;
use common::chain::timelock::OutputTimeLock::ForBlockCount;
use common::chain::tokens::{Metadata, TokenId, TokenIssuance};
use common::chain::{
    ChainConfig, Destination, PoolId, Transaction, TxInput, TxOutput, UtxoOutPoint,
};
use common::primitives::per_thousand::PerThousand;
use common::primitives::{Amount, BlockHeight};
use crypto::vrf::VRFPublicKey;
use utils::ensure;
use wallet_types::currency::Currency;
use wallet_types::partially_signed_transaction::{
    InfoId, PartiallySignedTransaction, TxAdditionalInfo,
};

use crate::account::PoolData;
use crate::destination_getters::{get_tx_output_destination, HtlcSpendingCondition};
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

    fees: BTreeMap<Currency, Amount>,
}

pub fn make_address_output(address: Address<Destination>, amount: Amount) -> TxOutput {
    TxOutput::Transfer(OutputValue::Coin(amount), address.into_object())
}

pub fn make_address_output_token(
    address: Address<Destination>,
    amount: Amount,
    token_id: TokenId,
) -> TxOutput {
    TxOutput::Transfer(
        OutputValue::TokenV1(token_id, amount),
        address.into_object(),
    )
}

pub fn make_issue_token_outputs(
    token_issuance: TokenIssuance,
    chain_config: &ChainConfig,
) -> WalletResult<Vec<TxOutput>> {
    tx_verifier::check_tokens_issuance(chain_config, &token_issuance)?;
    let issuance_output = TxOutput::IssueFungibleToken(Box::new(token_issuance));

    Ok(vec![issuance_output])
}

pub fn make_mint_token_outputs(
    token_id: TokenId,
    amount: Amount,
    address: Address<Destination>,
) -> Vec<TxOutput> {
    let destination = address.into_object();
    let mint_output = TxOutput::Transfer(OutputValue::TokenV1(token_id, amount), destination);

    vec![mint_output]
}

pub fn make_unmint_token_outputs(token_id: TokenId, amount: Amount) -> Vec<TxOutput> {
    let burn_tokens = TxOutput::Burn(OutputValue::TokenV1(token_id, amount));
    vec![burn_tokens]
}

pub fn make_create_delegation_output(address: Address<Destination>, pool_id: PoolId) -> TxOutput {
    TxOutput::CreateDelegationId(address.into_object(), pool_id)
}

pub fn make_address_output_from_delegation(
    chain_config: &ChainConfig,
    address: Address<Destination>,
    amount: Amount,
    current_block_height: BlockHeight,
) -> TxOutput {
    let num_blocks_to_lock =
        chain_config.staking_pool_spend_maturity_block_count(current_block_height);

    TxOutput::LockThenTransfer(
        OutputValue::Coin(amount),
        address.into_object(),
        ForBlockCount(num_blocks_to_lock.to_int()),
    )
}

pub fn make_decommission_stake_pool_output(
    chain_config: &ChainConfig,
    destination: Destination,
    amount: Amount,
    current_block_height: BlockHeight,
) -> WalletResult<TxOutput> {
    let num_blocks_to_lock =
        chain_config.staking_pool_spend_maturity_block_count(current_block_height);

    Ok(TxOutput::LockThenTransfer(
        OutputValue::Coin(amount),
        destination,
        ForBlockCount(num_blocks_to_lock.to_int()),
    ))
}

/// Helper struct to reduce the number of arguments passed around.
pub struct StakePoolCreationArguments {
    pub amount: Amount,
    pub margin_ratio_per_thousand: PerThousand,
    pub cost_per_block: Amount,
    pub decommission_key: Destination,
    pub staker_key: Option<Destination>,
    pub vrf_public_key: Option<VRFPublicKey>,
}

/// Same as StakePoolCreationArguments, but with non-optional staker_key and vrf_public_key.
pub struct StakePoolCreationResolvedArguments {
    pub amount: Amount,
    pub margin_ratio_per_thousand: PerThousand,
    pub cost_per_block: Amount,
    pub decommission_key: Destination,
    pub staker_key: Destination,
    pub vrf_public_key: VRFPublicKey,
}

pub fn make_stake_output(
    pool_id: PoolId,
    arguments: StakePoolCreationResolvedArguments,
) -> TxOutput {
    let stake_data = StakePoolData::new(
        arguments.amount,
        arguments.staker_key,
        arguments.vrf_public_key,
        arguments.decommission_key,
        arguments.margin_ratio_per_thousand,
        arguments.cost_per_block,
    );
    TxOutput::CreateStakePool(pool_id, stake_data.into())
}

pub fn make_data_deposit_output(
    chain_config: &ChainConfig,
    data: Vec<u8>,
    current_block_height: BlockHeight,
) -> WalletResult<Vec<TxOutput>> {
    ensure!(
        data.len() <= chain_config.data_deposit_max_size(current_block_height),
        WalletError::DataDepositToBig(
            data.len(),
            chain_config.data_deposit_max_size(current_block_height)
        )
    );
    ensure!(!data.is_empty(), WalletError::EmptyDataDeposit);

    Ok(vec![TxOutput::DataDeposit(data)])
}

pub struct IssueNftArguments {
    pub metadata: Metadata,
    pub destination: Destination,
}

impl SendRequest {
    pub fn new() -> Self {
        Self {
            flags: 0,
            utxos: Vec::new(),
            destinations: Vec::new(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            fees: BTreeMap::new(),
        }
    }

    pub fn add_fee(&mut self, currency: Currency, fee: Amount) -> WalletResult<()> {
        let prev_fee = self.fees.entry(currency).or_insert(Amount::ZERO);
        *prev_fee = (*prev_fee + fee).ok_or(WalletError::FeeAmountOverflow)?;
        Ok(())
    }

    pub fn from_transaction<'a, PoolDataGetter>(
        transaction: Transaction,
        utxos: Vec<TxOutput>,
        pool_data_getter: &PoolDataGetter,
    ) -> WalletResult<Self>
    where
        PoolDataGetter: Fn(&PoolId) -> Option<&'a PoolData>,
    {
        let destinations = utxos
            .iter()
            .map(|utxo| {
                get_tx_output_destination(utxo, &pool_data_getter, HtlcSpendingCondition::Skip)
                    .ok_or_else(|| {
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
            fees: BTreeMap::new(),
        })
    }

    pub fn inputs(&self) -> &[TxInput] {
        &self.inputs
    }

    pub fn destinations(&self) -> &[Destination] {
        &self.destinations
    }

    pub fn utxos(&self) -> &[Option<TxOutput>] {
        &self.utxos
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

    pub fn with_inputs<'a, PoolDataGetter>(
        mut self,
        utxos: impl IntoIterator<Item = (TxInput, TxOutput)>,
        pool_data_getter: &PoolDataGetter,
    ) -> WalletResult<Self>
    where
        PoolDataGetter: Fn(&PoolId) -> Option<&'a PoolData>,
    {
        for (outpoint, txo) in utxos {
            self.inputs.push(outpoint);
            self.destinations.push(
                get_tx_output_destination(&txo, &pool_data_getter, HtlcSpendingCondition::Skip)
                    .ok_or_else(|| {
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

    pub fn get_fees(&mut self) -> BTreeMap<Currency, Amount> {
        take(&mut self.fees)
    }

    pub fn into_partially_signed_tx(
        self,
        additional_info: BTreeMap<InfoId, TxAdditionalInfo>,
    ) -> WalletResult<PartiallySignedTransaction> {
        let num_inputs = self.inputs.len();
        let destinations = self.destinations.into_iter().map(Some).collect();
        let utxos = self.utxos;
        let tx = Transaction::new(self.flags, self.inputs, self.outputs)?;

        let ptx = PartiallySignedTransaction::new(
            tx,
            vec![None; num_inputs],
            utxos,
            destinations,
            None,
            additional_info,
        )?;
        Ok(ptx)
    }
}

pub enum SelectedInputs {
    Utxos(Vec<UtxoOutPoint>),
    Inputs(Vec<(UtxoOutPoint, TxOutput)>),
}

impl SelectedInputs {
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Utxos(utxos) => utxos.is_empty(),
            Self::Inputs(inputs) => inputs.is_empty(),
        }
    }
}
