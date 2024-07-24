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

//! Support types for presenting data in user-facing settings

mod balances;
mod block_info;
mod seed_phrase;
mod standalone_key;
mod transaction;

pub use balances::Balances;
pub use block_info::{BlockInfo, CreatedBlockInfo};
pub use common::primitives::amount::RpcAmountOut;
use common::{
    chain::{
        output_value::OutputValue,
        tokens::{RPCTokenInfo, TokenId},
        ChainConfig, Destination, TxOutput,
    },
    primitives::{DecimalAmount, H256},
};
pub use seed_phrase::SeedWithPassPhrase;
pub use standalone_key::AccountStandaloneKeyDetails;
pub use transaction::{
    InspectTransaction, SignatureStats, TransactionToInspect, ValidatedSignatures,
};
use utils::ensure;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, rpc_description::HasValueHint)]
pub struct WalletInfo {
    pub wallet_id: H256,
    pub account_names: Vec<Option<String>>,
}

/// Similar to TxOutput but without specifying the concrete currency.
///
/// For now it only has the `Transfer` variant, but more can be added when needed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum GenericTxOutput {
    Transfer(DecimalAmount, Destination),
}

impl GenericTxOutput {
    pub fn into_coin_output(
        self,
        chain_config: &ChainConfig,
    ) -> Result<TxOutput, GenericTxOutputError> {
        self.into_tx_output(|amount| {
            let decimals = chain_config.coin_decimals();
            Ok(OutputValue::Coin(amount.to_amount(decimals).ok_or(
                GenericTxOutputError::AmountNotConvertible(amount, decimals),
            )?))
        })
    }

    pub fn into_token_output(
        self,
        token_info: &RPCTokenInfo,
    ) -> Result<TxOutput, GenericTxOutputError> {
        self.into_tx_output(|amount| {
            let decimals = token_info.token_number_of_decimals();
            Ok(OutputValue::TokenV1(
                token_info.token_id(),
                amount
                    .to_amount(decimals)
                    .ok_or(GenericTxOutputError::AmountNotConvertible(amount, decimals))?,
            ))
        })
    }

    fn into_tx_output(
        self,
        value_maker: impl Fn(DecimalAmount) -> Result<OutputValue, GenericTxOutputError>,
    ) -> Result<TxOutput, GenericTxOutputError> {
        match self {
            GenericTxOutput::Transfer(amount, dest) => {
                let output_val = value_maker(amount)?;
                Ok(TxOutput::Transfer(output_val, dest))
            }
        }
    }
}

/// GenericTxOutput intended to send a specific token.
///
/// The difference from TxOutput is that it only contains DecimalAmount and not Amount
/// (to calculate the latter you need to know the number of decimals for the token).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenericTxTokenOutput {
    pub token_id: TokenId,
    pub output: GenericTxOutput,
}

impl GenericTxTokenOutput {
    pub fn into_tx_output(
        self,
        token_info: &RPCTokenInfo,
    ) -> Result<TxOutput, GenericTxOutputError> {
        ensure!(
            self.token_id == token_info.token_id(),
            GenericTxOutputError::UnexpectedTokenId {
                expected: self.token_id,
                actual: token_info.token_id(),
            }
        );

        self.output.into_token_output(token_info)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum GenericTxOutputError {
    #[error("Decimal amount {0} can't be converted to Amount with {1} decimals")]
    AmountNotConvertible(DecimalAmount, u8),
    #[error("Unexpected token id {actual} (expecting {expected})")]
    UnexpectedTokenId { expected: TokenId, actual: TokenId },
}

impl rpc_description::HasValueHint for GenericTxOutput {
    const HINT_SER: rpc_description::ValueHint = rpc_description::ValueHint::GENERIC_OBJECT;
}

impl rpc_description::HasValueHint for GenericTxTokenOutput {
    const HINT_SER: rpc_description::ValueHint = rpc_description::ValueHint::GENERIC_OBJECT;
}
