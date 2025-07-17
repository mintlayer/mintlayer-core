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
use wallet_types::{seed_phrase::StoreSeedPhrase, wallet_type::WalletType};

use crate::{
    signer::{software_signer::SoftwareSignerProvider, SignerProvider},
    wallet::create_wallet_in_memory,
    wallet_events::WalletEventsNoOp,
    DefaultWallet, Wallet,
};

pub fn create_wallet_with_mnemonic(
    chain_config: Arc<ChainConfig>,
    mnemonic: &str,
) -> DefaultWallet {
    let db = create_wallet_in_memory().unwrap();
    let genesis_block_id = chain_config.genesis_block_id();
    Wallet::create_new_wallet(
        chain_config.clone(),
        db,
        (BlockHeight::new(0), genesis_block_id),
        WalletType::Hot,
        |db_tx| {
            Ok(SoftwareSignerProvider::new_from_mnemonic(
                chain_config,
                db_tx,
                mnemonic,
                None,
                StoreSeedPhrase::DoNotStore,
            )?)
        },
    )
    .unwrap()
    .wallet()
    .unwrap()
}

pub fn scan_wallet<B, P>(wallet: &mut Wallet<B, P>, height: BlockHeight, blocks: Vec<Block>)
where
    B: storage::Backend + 'static,
    P: SignerProvider,
{
    for account in wallet.get_best_block().keys() {
        wallet
            .scan_new_blocks(*account, height, blocks.clone(), &WalletEventsNoOp)
            .unwrap();
    }

    wallet
        .scan_new_blocks_unused_account(height, blocks, &WalletEventsNoOp)
        .unwrap();
}
