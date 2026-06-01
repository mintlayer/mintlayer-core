// Copyright (c) 2021-2025 RBB S.r.l
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

//! A module for test utilities that depend on this crate and that are supposed to be used both
//! in this crate's unit tests and in some other crates.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use common::{
    chain::{Block, ChainConfig},
    primitives::BlockHeight,
};
use wallet_storage::{DefaultBackend, Store};
use wallet_types::{
    seed_phrase::StoreSeedPhrase,
    wallet_type::{WalletControllerMode, WalletType},
};

use crate::{
    signer::{software_signer::SoftwareSignerProvider, SignerProvider},
    wallet::create_wallet_in_memory,
    wallet_events::WalletEventsNoOp,
    DefaultWallet, Wallet,
};

pub async fn create_wallet_with_mnemonic(
    chain_config: Arc<ChainConfig>,
    mnemonic: &str,
) -> DefaultWallet {
    create_wallet_with_type_and_mnemonic(chain_config, WalletType::Hot, mnemonic).await
}

pub async fn create_wallet_with_type_and_mnemonic(
    chain_config: Arc<ChainConfig>,
    wallet_type: WalletType,
    mnemonic: &str,
) -> DefaultWallet {
    create_wallet_generic(chain_config, wallet_type, mnemonic, None).await
}

pub fn create_named_in_memory_backend(db_name: &str) -> DefaultBackend {
    DefaultBackend::new_named_in_memory(db_name)
}

pub fn create_named_in_memory_store(db_name: &str) -> Store<DefaultBackend> {
    Store::new(create_named_in_memory_backend(db_name)).unwrap()
}

pub async fn create_wallet_with_mnemonic_and_named_db(
    chain_config: Arc<ChainConfig>,
    mnemonic: &str,
    db_name: &str,
) -> DefaultWallet {
    create_wallet_generic(chain_config, WalletType::Hot, mnemonic, Some(db_name)).await
}

pub async fn create_wallet_generic(
    chain_config: Arc<ChainConfig>,
    wallet_type: WalletType,
    mnemonic: &str,
    db_name: Option<&str>,
) -> DefaultWallet {
    let db = if let Some(db_name) = db_name {
        create_named_in_memory_store(db_name)
    } else {
        create_wallet_in_memory().unwrap()
    };
    let genesis_block_id = chain_config.genesis_block_id();
    Wallet::create_new_wallet(
        chain_config.clone(),
        db,
        (BlockHeight::new(0), genesis_block_id),
        wallet_type,
        async |db_tx| {
            SoftwareSignerProvider::new_from_mnemonic(
                chain_config,
                db_tx,
                mnemonic,
                None,
                StoreSeedPhrase::DoNotStore,
            )
            .map_err(Into::into)
        },
    )
    .await
    .unwrap()
    .wallet()
    .unwrap()
}

pub async fn load_wallet(
    chain_config: Arc<ChainConfig>,
    db_name: &str,
    controller_mode: WalletControllerMode,
    force_change_wallet_type: bool,
) -> DefaultWallet {
    let db = create_named_in_memory_store(db_name);

    Wallet::load_wallet(
        Arc::clone(&chain_config),
        db,
        None,
        |_| Ok(()),
        controller_mode,
        force_change_wallet_type,
        async |db_tx| SoftwareSignerProvider::load_from_database(chain_config, &db_tx),
    )
    .await
    .unwrap()
    .wallet()
    .unwrap()
}

pub async fn scan_wallet<B, P>(wallet: &mut Wallet<B, P>, height: BlockHeight, blocks: Vec<Block>)
where
    B: storage::BackendWithSendableTransactions + 'static,
    P: SignerProvider,
{
    for account in wallet.get_best_block().keys() {
        wallet
            .scan_new_blocks(*account, height, blocks.clone(), &WalletEventsNoOp)
            .unwrap();
    }

    wallet
        .scan_new_blocks_unused_account(height, blocks, &WalletEventsNoOp)
        .await
        .unwrap();
}
