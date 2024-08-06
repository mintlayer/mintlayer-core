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
use bip39::{Language, Mnemonic};
pub use block_info::{BlockInfo, CreatedBlockInfo};
pub use common::primitives::amount::RpcAmountOut;
use common::primitives::H256;
pub use seed_phrase::SeedWithPassPhrase;
pub use standalone_key::AccountStandaloneKeyDetails;
pub use transaction::{
    InspectTransaction, SignatureStats, TransactionToInspect, ValidatedSignatures,
};
use wallet_types::seed_phrase::StoreSeedPhrase;

use crate::mnemonic;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, rpc_description::HasValueHint)]
pub struct WalletInfo {
    pub wallet_id: H256,
    pub account_names: Vec<Option<String>>,
}

pub enum CreatedWallet {
    UserProvidedMnemonic,
    NewlyGeneratedMnemonic(Mnemonic, Option<String>),
}

#[derive(Debug, Clone)]
pub enum WalletTypeArgs {
    Software {
        mnemonic: Option<String>,
        passphrase: Option<String>,
        store_seed_phrase: StoreSeedPhrase,
    },
    #[cfg(feature = "trezor")]
    Trezor,
}

impl WalletTypeArgs {
    pub fn user_supplied_menmonic(&self) -> bool {
        match self {
            Self::Software {
                mnemonic,
                passphrase: _,
                store_seed_phrase: _,
            } => mnemonic.is_some(),
            #[cfg(feature = "trezor")]
            Self::Trezor => false,
        }
    }

    pub fn parse_mnemonic(
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
                            CreatedWallet::NewlyGeneratedMnemonic(mnemonic, passphrase.clone()),
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
            Self::Trezor => Ok((
                WalletTypeArgsComputed::Trezor,
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
    Trezor,
}
