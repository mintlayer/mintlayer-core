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

use std::collections::BTreeSet;

pub use balances::Balances;
use bip39::{Language, Mnemonic};
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
    InspectTransaction, NewTransaction, SignatureStats, TransactionToInspect, ValidatedSignatures,
};
use utils::ensure;
use wallet::signer::trezor_signer::FoundDevice;
use wallet_types::{
    scan_blockchain::ScanBlockchain,
    seed_phrase::StoreSeedPhrase,
    wallet_type::{WalletControllerMode, WalletType},
};

use crate::mnemonic;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, rpc_description::HasValueHint)]
pub struct WalletInfo {
    pub wallet_id: H256,
    pub account_names: Vec<Option<String>>,
}

// A struct that represents sending a particular amount of unspecified currency.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenericCurrencyTransfer {
    pub amount: DecimalAmount,
    pub destination: Destination,
}

impl GenericCurrencyTransfer {
    pub fn into_coin_tx_output(
        self,
        chain_config: &ChainConfig,
    ) -> Result<TxOutput, GenericCurrencyTransferToTxOutputConversionError> {
        let decimals = chain_config.coin_decimals();
        let output_val = OutputValue::Coin(self.amount.to_amount(decimals).ok_or(
            GenericCurrencyTransferToTxOutputConversionError::AmountNotConvertible(
                self.amount,
                decimals,
            ),
        )?);

        Ok(TxOutput::Transfer(output_val, self.destination))
    }

    pub fn into_token_tx_output(
        self,
        token_info: &RPCTokenInfo,
    ) -> Result<TxOutput, GenericCurrencyTransferToTxOutputConversionError> {
        let decimals = token_info.token_number_of_decimals();
        let output_val = OutputValue::TokenV1(
            token_info.token_id(),
            self.amount.to_amount(decimals).ok_or(
                GenericCurrencyTransferToTxOutputConversionError::AmountNotConvertible(
                    self.amount,
                    decimals,
                ),
            )?,
        );

        Ok(TxOutput::Transfer(output_val, self.destination))
    }
}

/// A struct that represents sending a specific token.
///
/// The difference from TxOutput::Transfer is that it only contains DecimalAmount and not Amount
/// (to calculate the latter you need to know the number of decimals for the token).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenericTokenTransfer {
    pub token_id: TokenId,
    pub amount: DecimalAmount,
    pub destination: Destination,
}

impl GenericTokenTransfer {
    pub fn into_currency_transfer(self) -> (TokenId, GenericCurrencyTransfer) {
        (
            self.token_id,
            GenericCurrencyTransfer {
                amount: self.amount,
                destination: self.destination,
            },
        )
    }

    pub fn into_tx_output(
        self,
        token_info: &RPCTokenInfo,
    ) -> Result<TxOutput, GenericCurrencyTransferToTxOutputConversionError> {
        ensure!(
            self.token_id == token_info.token_id(),
            GenericCurrencyTransferToTxOutputConversionError::UnexpectedTokenId {
                expected: self.token_id,
                actual: token_info.token_id(),
            }
        );

        self.into_currency_transfer().1.into_token_tx_output(token_info)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum GenericCurrencyTransferToTxOutputConversionError {
    #[error("Decimal amount {0} can't be converted to Amount with {1} decimals")]
    AmountNotConvertible(DecimalAmount, u8),
    #[error("Unexpected token id {actual} (expecting {expected})")]
    UnexpectedTokenId { expected: TokenId, actual: TokenId },
}

impl rpc_description::HasValueHint for GenericCurrencyTransfer {
    const HINT_SER: rpc_description::ValueHint = rpc_description::ValueHint::GENERIC_OBJECT;
}

impl rpc_description::HasValueHint for GenericTokenTransfer {
    const HINT_SER: rpc_description::ValueHint = rpc_description::ValueHint::GENERIC_OBJECT;
}

pub enum CreatedWallet {
    UserProvidedMnemonic,
    NewlyGeneratedMnemonic(Mnemonic),
    #[cfg(feature = "trezor")]
    TrezorDeviceSelection(Vec<FoundDevice>),
}

pub enum OpenedWallet {
    Opened,
    #[cfg(feature = "trezor")]
    TrezorDeviceSelection(Vec<FoundDevice>),
}

#[derive(Debug, Clone)]
pub enum WalletTypeArgs {
    Software {
        mnemonic: Option<String>,
        passphrase: Option<String>,
        store_seed_phrase: StoreSeedPhrase,
    },
    #[cfg(feature = "trezor")]
    Trezor { device_id: Option<String> },
}

#[derive(Debug, Clone, Copy)]
pub struct WalletCreationOptions {
    /// should scan the blockchain and whether to wait for it or not
    pub scan_blockchain: ScanBlockchain,
    /// Can overwrite an existing wallet file if selected from the GUI wallet
    pub overwrite_wallet_file: bool,
}

impl WalletTypeArgs {
    pub fn wallet_type(&self, controller_mode: WalletControllerMode) -> WalletType {
        match self {
            Self::Software {
                mnemonic: _,
                passphrase: _,
                store_seed_phrase: _,
            } => controller_mode.into(),
            #[cfg(feature = "trezor")]
            Self::Trezor { device_id: _ } => WalletType::Trezor,
        }
    }

    pub fn parse_or_generate_mnemonic_if_needed(
        self,
    ) -> Result<(WalletTypeArgsComputed, CreatedWallet), mnemonic::Error> {
        match self {
            Self::Software {
                mnemonic,
                passphrase,
                store_seed_phrase,
            } => {
                let language = Language::English;
                let (mnemonic, created_wallet) = match &mnemonic {
                    Some(mnemonic) => {
                        let mnemonic = mnemonic::parse_mnemonic(language, mnemonic)?;
                        (mnemonic, CreatedWallet::UserProvidedMnemonic)
                    }
                    None => {
                        let mnemonic = mnemonic::generate_new_mnemonic(language);
                        (
                            mnemonic.clone(),
                            CreatedWallet::NewlyGeneratedMnemonic(mnemonic),
                        )
                    }
                };

                Ok((
                    WalletTypeArgsComputed::Software {
                        mnemonic,
                        passphrase,
                        store_seed_phrase,
                    },
                    created_wallet,
                ))
            }

            #[cfg(feature = "trezor")]
            Self::Trezor { device_id } => Ok((
                WalletTypeArgsComputed::Trezor { device_id },
                CreatedWallet::UserProvidedMnemonic,
            )),
        }
    }
}

pub enum WalletTypeArgsComputed {
    Software {
        mnemonic: Mnemonic,
        passphrase: Option<String>,
        store_seed_phrase: StoreSeedPhrase,
    },
    #[cfg(feature = "trezor")]
    Trezor { device_id: Option<String> },
}

pub enum SweepFromAddresses {
    All,
    SpecificAddresses(BTreeSet<Destination>),
}

impl SweepFromAddresses {
    pub fn should_sweep_address(&self, dest: &Destination) -> bool {
        match self {
            Self::All => true,
            Self::SpecificAddresses(destinations) => destinations.contains(dest),
        }
    }
}
