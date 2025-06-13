// Copyright (c) 2025 RBB S.r.l
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

pub mod generic_fixed_signature_tests;
pub mod generic_tests;

use std::sync::Arc;

use common::chain::ChainConfig;
use crypto::key::{hdkd::u31::U31, PredefinedSigAuxDataProvider};
use wallet_storage::StoreTxRwUnlocked;
use wallet_types::seed_phrase::StoreSeedPhrase;

use crate::{
    key_chain::{AccountKeyChainImplSoftware, MasterKeyChain, LOOKAHEAD_SIZE},
    signer::software_signer::SoftwareSigner,
    Account,
};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[ctor::ctor]
fn init() {
    logging::init_logging();
}

fn account_from_mnemonic<B: storage::Backend>(
    chain_config: &Arc<ChainConfig>,
    db_tx: &mut StoreTxRwUnlocked<B>,
    account_index: U31,
) -> Account<AccountKeyChainImplSoftware> {
    let master_key_chain = MasterKeyChain::new_from_mnemonic(
        chain_config.clone(),
        db_tx,
        MNEMONIC,
        None,
        StoreSeedPhrase::DoNotStore,
    )
    .unwrap();

    let key_chain = master_key_chain
        .create_account_key_chain(db_tx, account_index, LOOKAHEAD_SIZE)
        .unwrap();
    Account::new(chain_config.clone(), db_tx, key_chain, None).unwrap()
}

pub fn make_software_signer(chain_config: Arc<ChainConfig>, account_index: U31) -> SoftwareSigner {
    SoftwareSigner::new(chain_config, account_index)
}

// Return a SoftwareSigner that will produce Trezor-like signatures.
pub fn make_deterministic_software_signer(
    chain_config: Arc<ChainConfig>,
    account_index: U31,
) -> SoftwareSigner {
    SoftwareSigner::new_with_sig_aux_data_provider(
        chain_config,
        account_index,
        Box::new(PredefinedSigAuxDataProvider),
    )
}

pub fn no_another_signer() -> Option<impl Fn(Arc<ChainConfig>, U31) -> SoftwareSigner> {
    None::<Box<dyn Fn(Arc<ChainConfig>, U31) -> SoftwareSigner>>
}
