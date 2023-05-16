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

use crate::key_chain::{make_account_path, LOOKAHEAD_SIZE};

use super::*;
use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        block::timestamp::BlockTimestamp,
        config::{create_mainnet, create_regtest, Builder, ChainType},
        timelock::OutputTimeLock,
        tokens::OutputValue,
        Destination, Genesis,
    },
};
use crypto::key::hdkd::{
    child_number::ChildNumber, derivable::Derivable, derivation_path::DerivationPath,
};
use wallet_types::account_info::DEFAULT_ACCOUNT_INDEX;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn get_address(
    chain_config: &ChainConfig,
    mnemonic: &str,
    account_index: U31,
    purpose: KeyPurpose,
    address_index: U31,
) -> Address {
    let root_key = MasterKeyChain::mnemonic_to_root_key(mnemonic, None).unwrap();
    let mut address_path = make_account_path(chain_config, account_index).into_vec();
    address_path.push(purpose.get_deterministic_index());
    address_path.push(ChildNumber::from_normal(address_index));
    let address_priv_key = root_key
        .derive_absolute_path(&DerivationPath::try_from(address_path).unwrap())
        .unwrap();
    Address::from_public_key(
        chain_config,
        &address_priv_key.to_public_key().into_public_key(),
    )
    .unwrap()
}

fn test_balance_from_genesis(utxos: Vec<TxOutput>, expected_balance: Amount) {
    let genesis = Genesis::new(
        String::new(),
        BlockTimestamp::from_int_seconds(1639975460),
        utxos,
    );
    let chain_config = Arc::new(Builder::new(ChainType::Mainnet).genesis_custom(genesis).build());

    let db = create_wallet_in_memory().unwrap();

    let mut wallet = Wallet::new_wallet(chain_config.clone(), db.clone(), MNEMONIC, None).unwrap();
    wallet.create_account(DEFAULT_ACCOUNT_INDEX).unwrap();

    let (coin_balance, _) = wallet.get_balance(DEFAULT_ACCOUNT_INDEX).unwrap();
    assert_eq!(coin_balance, expected_balance);
    drop(wallet);

    let wallet = Wallet::load_wallet(chain_config, db).unwrap();
    let (coin_balance, _) = wallet.get_balance(DEFAULT_ACCOUNT_INDEX).unwrap();
    assert_eq!(coin_balance, expected_balance);
}

#[test]
fn wallet_creation_in_memory() {
    let chain_config = Arc::new(create_regtest());
    let db = create_wallet_in_memory().unwrap();

    match Wallet::load_wallet(chain_config.clone(), db.clone()) {
        Ok(_) => panic!("Wallet loading should fail"),
        Err(err) => assert_eq!(err, WalletError::WalletNotInitialized),
    }

    let wallet = Wallet::new_wallet(chain_config.clone(), db.clone(), MNEMONIC, None).unwrap();
    drop(wallet);

    let _wallet = Wallet::load_wallet(chain_config, db).unwrap();
}

#[test]
fn block_scan_genesis() {
    let genesis_amount = Amount::from_atoms(12345);
    let genesis_output = TxOutput::Transfer(
        OutputValue::Coin(genesis_amount),
        Destination::AnyoneCanSpend,
    );

    test_balance_from_genesis(vec![genesis_output.clone()], genesis_amount);

    let genesis_amount_2 = Amount::from_atoms(54321);
    let genesis_output_2 = TxOutput::LockThenTransfer(
        OutputValue::Coin(genesis_amount_2),
        Destination::AnyoneCanSpend,
        OutputTimeLock::UntilHeight(BlockHeight::zero()),
    );

    test_balance_from_genesis(
        vec![genesis_output, genesis_output_2],
        (genesis_amount + genesis_amount_2).unwrap(),
    );

    let address_indexes = [0, LOOKAHEAD_SIZE - 1, LOOKAHEAD_SIZE];
    let chain_config = Arc::new(create_mainnet());
    for purpose in KeyPurpose::ALL {
        for address_index in address_indexes {
            let address_index: U31 = address_index.try_into().unwrap();
            let address = get_address(
                &chain_config,
                MNEMONIC,
                DEFAULT_ACCOUNT_INDEX,
                purpose,
                address_index,
            );

            let genesis_amount = Amount::from_atoms(23456);
            let genesis_output = TxOutput::Transfer(
                OutputValue::Coin(genesis_amount),
                Destination::Address(PublicKeyHash::try_from(&address).unwrap()),
            );

            if address_index.into_u32() == LOOKAHEAD_SIZE {
                test_balance_from_genesis(vec![genesis_output], Amount::ZERO);
            } else {
                test_balance_from_genesis(vec![genesis_output], genesis_amount);
            }
        }
    }
}
